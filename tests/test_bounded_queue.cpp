#include <gtest/gtest.h>
#include "netguard/pipeline/bounded_queue.hpp"
#include <thread>
#include <vector>
#include <atomic>

using namespace netguard;

TEST(BoundedQueueTest, BasicPushPop) {
    BoundedQueue<int> q(5);
    EXPECT_TRUE(q.empty());
    EXPECT_EQ(q.size(), 0);

    EXPECT_TRUE(q.push(10));
    EXPECT_TRUE(q.push(20));
    EXPECT_EQ(q.size(), 2);

    int val = 0;
    EXPECT_TRUE(q.pop(val));
    EXPECT_EQ(val, 10);
    EXPECT_TRUE(q.pop(val));
    EXPECT_EQ(val, 20);

    EXPECT_TRUE(q.empty());
}

TEST(BoundedQueueTest, ConcurrentPushPop) {
    const size_t NUM_PRODUCERS = 4;
    const size_t NUM_CONSUMERS = 4;
    const size_t ITEMS_PER_PRODUCER = 5000;

    BoundedQueue<int> q(100);
    std::atomic<uint64_t> total_pushed{0};
    std::atomic<uint64_t> total_popped{0};

    std::vector<std::thread> producers;
    std::vector<std::thread> consumers;

    for (size_t i = 0; i < NUM_PRODUCERS; ++i) {
        producers.emplace_back([&q, &total_pushed, ITEMS_PER_PRODUCER]() {
            for (size_t k = 0; k < ITEMS_PER_PRODUCER; ++k) {
                if (q.push(1)) {
                    total_pushed++;
                }
            }
        });
    }

    for (size_t i = 0; i < NUM_CONSUMERS; ++i) {
        consumers.emplace_back([&q, &total_popped]() {
            int val = 0;
            while (q.pop(val)) {
                total_popped++;
            }
        });
    }

    for (auto& t : producers) t.join();
    q.stop();
    for (auto& t : consumers) t.join();

    EXPECT_EQ(total_pushed.load(), NUM_PRODUCERS * ITEMS_PER_PRODUCER);
    EXPECT_EQ(total_popped.load(), total_pushed.load());
}

TEST(BoundedQueueTest, StopUnblocksWaitingThreads) {
    BoundedQueue<int> q(2);
    q.push(1);
    q.push(2);

    std::atomic<bool> push_blocked_finished{false};
    std::thread producer([&q, &push_blocked_finished]() {
        q.push(3); // Will block because queue is full
        push_blocked_finished = true;
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_FALSE(push_blocked_finished.load());

    q.stop(); // Should unblock
    producer.join();

    EXPECT_TRUE(push_blocked_finished.load());
}
