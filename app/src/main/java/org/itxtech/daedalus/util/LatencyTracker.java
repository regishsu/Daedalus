package org.itxtech.daedalus.util;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

public class LatencyTracker {

    private static final int WINDOW_SIZE = 10;
    private static final double RECENT_WEIGHT = 0.7;

    private final Map<String, LinkedList<Long>> latencyHistory = new HashMap<>();
    private final Map<String, Integer> failCount = new HashMap<>();

    public synchronized void record(String serverAddress, long latencyMs) {
        if (latencyMs < 0) {
            recordFailure(serverAddress);
            return;
        }
        failCount.put(serverAddress, 0);

        LinkedList<Long> history = latencyHistory.get(serverAddress);
        if (history == null) {
            history = new LinkedList<>();
            latencyHistory.put(serverAddress, history);
        }
        history.addLast(latencyMs);
        if (history.size() > WINDOW_SIZE) {
            history.removeFirst();
        }
    }

    public synchronized void recordFailure(String serverAddress) {
        Integer count = failCount.get(serverAddress);
        if (count == null) {
            count = 0;
        }
        failCount.put(serverAddress, count + 1);
    }

    public synchronized long getWeightedAverage(String serverAddress) {
        LinkedList<Long> history = latencyHistory.get(serverAddress);
        if (history == null || history.isEmpty()) {
            return -1;
        }

        if (history.size() == 1) {
            return history.getFirst();
        }

        long sum = 0;
        int size = history.size();
        int recentCount = (int) Math.ceil(size * RECENT_WEIGHT);
        int olderCount = size - recentCount;

        for (int i = 0; i < olderCount; i++) {
            sum += history.get(i);
        }
        for (int i = olderCount; i < size; i++) {
            sum += history.get(i);
        }

        long olderSum = 0;
        for (int i = 0; i < olderCount; i++) {
            olderSum += history.get(i);
        }
        long recentSum = sum - olderSum;

        if (olderCount > 0 && recentCount > 0) {
            long olderAvg = olderSum / olderCount;
            long recentAvg = recentSum / recentCount;
            return (long) (olderAvg * (1 - RECENT_WEIGHT) + recentAvg * RECENT_WEIGHT);
        }

        return sum / size;
    }

    public synchronized int getFailCount(String serverAddress) {
        Integer count = failCount.get(serverAddress);
        return count == null ? 0 : count;
    }

    public synchronized void clear() {
        latencyHistory.clear();
        failCount.clear();
    }
}
