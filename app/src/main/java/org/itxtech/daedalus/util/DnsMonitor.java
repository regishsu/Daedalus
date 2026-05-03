package org.itxtech.daedalus.util;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;

import androidx.core.app.NotificationCompat;

import org.itxtech.daedalus.Daedalus;
import org.itxtech.daedalus.R;
import org.itxtech.daedalus.server.AbstractDnsServer;
import org.itxtech.daedalus.server.DnsServer;
import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnsmessage.Question;
import org.minidns.record.Record;
import org.minidns.source.NetworkDataSource;

import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.Random;

public class DnsMonitor {

    private static final String TAG = "DnsMonitor";
    private static final String CHANNEL_ID = "daedalus_dns_monitor_channel";
    private static final String CHANNEL_NAME = "Daedalus DNS Monitor";
    private static final int NOTIFICATION_ID = 1;

    private static final String DEFAULT_TEST_DOMAIN = "google.com";
    private static final long DEFAULT_PROBE_INTERVAL = 30000;
    private static final int DEFAULT_SWITCH_THRESHOLD = 3;
    private static final long DEFAULT_LATENCY_THRESHOLD = 100;

    private static DnsMonitor instance;

    private final LatencyTracker tracker = new LatencyTracker();
    private volatile boolean running = false;
    private Thread monitorThread;

    private AbstractDnsServer primaryServer;
    private AbstractDnsServer secondaryServer;
    private Context context;

    private long probeInterval = DEFAULT_PROBE_INTERVAL;
    private int switchThreshold = DEFAULT_SWITCH_THRESHOLD;
    private long latencyThreshold = DEFAULT_LATENCY_THRESHOLD;

    private int consecutiveSlowCount = 0;
    private AbstractDnsServer lastSlowServer = null;

    public static synchronized DnsMonitor getInstance() {
        if (instance == null) {
            instance = new DnsMonitor();
        }
        return instance;
    }

    private DnsMonitor() {
    }

    public void start(Context context, AbstractDnsServer primary, AbstractDnsServer secondary) {
        if (running) {
            return;
        }
        this.context = context.getApplicationContext();
        this.primaryServer = primary;
        this.secondaryServer = secondary;

        try {
            probeInterval = Integer.parseInt(Daedalus.getPrefs().getString("settings_dns_probe_interval", "30")) * 1000L;
        } catch (NumberFormatException e) {
            probeInterval = DEFAULT_PROBE_INTERVAL;
        }
        if (probeInterval <= 0) probeInterval = DEFAULT_PROBE_INTERVAL;

        try {
            switchThreshold = Integer.parseInt(Daedalus.getPrefs().getString("settings_dns_switch_threshold", "3"));
        } catch (NumberFormatException e) {
            switchThreshold = DEFAULT_SWITCH_THRESHOLD;
        }
        if (switchThreshold <= 0) switchThreshold = DEFAULT_SWITCH_THRESHOLD;

        try {
            latencyThreshold = Integer.parseInt(Daedalus.getPrefs().getString("settings_dns_latency_threshold", "100"));
        } catch (NumberFormatException e) {
            latencyThreshold = DEFAULT_LATENCY_THRESHOLD;
        }
        if (latencyThreshold <= 0) latencyThreshold = DEFAULT_LATENCY_THRESHOLD;

        running = true;
        monitorThread = new Thread(this::monitorLoop, "DnsMonitor");
        monitorThread.start();
        Logger.info("DnsMonitor started");
    }

    public void stop() {
        running = false;
        if (monitorThread != null) {
            monitorThread.interrupt();
            monitorThread = null;
        }
        Logger.info("DnsMonitor stopped");
    }

    public LatencyTracker getTracker() {
        return tracker;
    }

    public void updateServers(AbstractDnsServer primary, AbstractDnsServer secondary) {
        this.primaryServer = primary;
        this.secondaryServer = secondary;
    }

    private void monitorLoop() {
        while (running) {
            try {
                if (primaryServer == null || secondaryServer == null) {
                    Thread.sleep(probeInterval);
                    continue;
                }

                long primaryLatency = probeServer(primaryServer);
                tracker.record(primaryServer.getAddress(), primaryLatency);

                long secondaryLatency = probeServer(secondaryServer);
                tracker.record(secondaryServer.getAddress(), secondaryLatency);

                if (shouldSwitch(primaryLatency, secondaryLatency)) {
                    performSwitch();
                }

                updateNotification();

                Thread.sleep(probeInterval);
            } catch (InterruptedException e) {
                break;
            } catch (Exception e) {
                Logger.logException(e);
            }
        }
    }

    private long probeServer(AbstractDnsServer server) {
        try {
            DnsMessage.Builder message = DnsMessage.builder()
                    .addQuestion(new Question(DEFAULT_TEST_DOMAIN, Record.TYPE.A))
                    .setId(new Random().nextInt())
                    .setRecursionDesired(true)
                    .setOpcode(DnsMessage.OPCODE.QUERY)
                    .setResponseCode(DnsMessage.RESPONSE_CODE.NO_ERROR)
                    .setQrFlag(false);

            InetAddress address;
            if (server.isHttpsServer()) {
                String host = org.itxtech.daedalus.provider.HttpsProvider.HTTPS_SUFFIX + server.getAddress();
                android.net.Uri uri = android.net.Uri.parse(host);
                address = InetAddress.getByName(uri.getHost());
            } else {
                address = InetAddress.getByName(server.getAddress());
            }

            int port = server.getPort();
            if (port <= 0) port = AbstractDnsServer.DNS_SERVER_DEFAULT_PORT;

            long startTime = System.currentTimeMillis();
            DnsMessage response = new DnsQuery().queryDns(message.build(), address, port);
            long endTime = System.currentTimeMillis();

            if (response != null && response.answerSection != null && response.answerSection.size() > 0) {
                return endTime - startTime;
            }
            return -1;
        } catch (SocketTimeoutException e) {
            return -1;
        } catch (Exception e) {
            Logger.logException(e);
            return -1;
        }
    }

    private boolean shouldSwitch(long primaryLatency, long secondaryLatency) {
        int primaryFails = tracker.getFailCount(primaryServer.getAddress());
        if (primaryFails >= switchThreshold) {
            Logger.info("DnsMonitor: Primary server failed " + primaryFails + " times, switching");
            return true;
        }

        long avgPrimary = tracker.getWeightedAverage(primaryServer.getAddress());
        long avgSecondary = tracker.getWeightedAverage(secondaryServer.getAddress());

        if (avgPrimary > 0 && avgSecondary > 0) {
            long diff = avgPrimary - avgSecondary;
            if (diff > latencyThreshold) {
                if (lastSlowServer == primaryServer) {
                    consecutiveSlowCount++;
                } else {
                    consecutiveSlowCount = 1;
                    lastSlowServer = primaryServer;
                }

                if (consecutiveSlowCount >= switchThreshold) {
                    Logger.info("DnsMonitor: Primary avg latency " + avgPrimary + "ms vs Secondary " + avgSecondary + "ms, switching");
                    return true;
                }
            } else {
                consecutiveSlowCount = 0;
                lastSlowServer = null;
            }
        }

        return false;
    }

    private void performSwitch() {
        AbstractDnsServer temp = primaryServer;
        primaryServer = secondaryServer;
        secondaryServer = temp;

        tracker.clear();
        consecutiveSlowCount = 0;
        lastSlowServer = null;

        Logger.info("DnsMonitor: Servers swapped - New primary: " + primaryServer.getAddress() +
                ", New secondary: " + secondaryServer.getAddress());

        showSwitchNotification(primaryServer.getAddress());
    }

    private void updateNotification() {
        if (context == null || !Daedalus.getPrefs().getBoolean("settings_notification", true)) {
            return;
        }

        try {
            NotificationManager manager = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
            if (manager == null) return;

            String content = "DNS: " + primaryServer.getAddress() + " | Queries: " + getQueryCount();

            NotificationCompat.Builder builder;
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                NotificationChannel channel = new NotificationChannel(CHANNEL_ID, CHANNEL_NAME, NotificationManager.IMPORTANCE_LOW);
                manager.createNotificationChannel(channel);
                builder = new NotificationCompat.Builder(context, CHANNEL_ID);
            } else {
                builder = new NotificationCompat.Builder(context);
            }

            builder.setWhen(0)
                    .setContentTitle(context.getString(R.string.notice_activated))
                    .setContentText(content)
                    .setSmallIcon(R.drawable.ic_security)
                    .setColor(context.getResources().getColor(R.color.colorPrimary))
                    .setOngoing(true)
                    .setAutoCancel(false);

            manager.notify(NOTIFICATION_ID, builder.build());
        } catch (Exception e) {
            Logger.logException(e);
        }
    }

    private long getQueryCount() {
        try {
            return org.itxtech.daedalus.provider.Provider.getDnsQueryTimesStatic();
        } catch (Exception e) {
            return 0;
        }
    }

    private void showSwitchNotification(String newPrimary) {
        if (context == null) return;

        try {
            NotificationManager manager = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
            if (manager == null) return;

            NotificationCompat.Builder builder;
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                NotificationChannel channel = new NotificationChannel(CHANNEL_ID, CHANNEL_NAME, NotificationManager.IMPORTANCE_LOW);
                manager.createNotificationChannel(channel);
                builder = new NotificationCompat.Builder(context, CHANNEL_ID);
            } else {
                builder = new NotificationCompat.Builder(context);
            }

            builder.setWhen(0)
                    .setContentTitle("DNS " + context.getString(R.string.notice_dns_switched))
                    .setContentText(newPrimary)
                    .setSmallIcon(R.drawable.ic_security)
                    .setColor(context.getResources().getColor(R.color.colorPrimary))
                    .setAutoCancel(true);

            manager.notify(NOTIFICATION_ID, builder.build());
        } catch (Exception e) {
            Logger.logException(e);
        }
    }

    public AbstractDnsServer getPrimaryServer() {
        return primaryServer;
    }

    public AbstractDnsServer getSecondaryServer() {
        return secondaryServer;
    }

    private static class DnsQuery extends NetworkDataSource {
        public DnsMessage queryDns(DnsMessage message, InetAddress address, int port) throws IOException {
            return queryUdp(message, address, port);
        }
    }
}
