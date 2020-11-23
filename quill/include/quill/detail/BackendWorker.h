/**
 * Copyright(c) 2020-present, Odysseas Georgoudis & quill contributors.
 * Distributed under the MIT License (http://opensource.org/licenses/MIT)
 */

#pragma once

#include "quill/TweakMe.h"

#include "quill/QuillError.h"                       // for QUILL_CATCH, QUILL...
#include "quill/detail/BacktraceLogRecordStorage.h" // for BacktraceLogRecordStorage
#include "quill/detail/BoundedSPSCQueue.h"          // for BoundedSPSCQueue<>...
#include "quill/detail/Config.h"                    // for Config
#include "quill/detail/HandlerCollection.h"         // for HandlerCollection
#include "quill/detail/LogDataNode.h"
#include "quill/detail/ThreadContext.h"           // for ThreadContext, Thr...
#include "quill/detail/ThreadContextCollection.h" // for ThreadContextColle...
#include "quill/detail/events/BaseEvent.h"        // for RecordBase
#include "quill/detail/misc/Attributes.h"         // for QUILL_ATTRIBUTE_HOT
#include "quill/detail/misc/Common.h"             // for QUILL_RDTSC_RESYNC...
#include "quill/detail/misc/FreeListAllocator.h"  // for FreeListAllocator..
#include "quill/detail/misc/Macros.h"             // for QUILL_LIKELY
#include "quill/detail/misc/Os.h"                 // for set_cpu_affinity, get_thread_id
#include "quill/detail/misc/RdtscClock.h"         // for RdtscClock
#include "quill/handlers/Handler.h"               // for Handler
#include <atomic>                                 // for atomic, memory_ord...
#include <cassert>                                // for assert
#include <chrono>                                 // for nanoseconds, milli...
#include <cstdint>                                // for uint16_t
#include <exception>                              // for exception
#include <functional>                             // for greater, function
#include <limits>                                 // for numeric_limits
#include <memory>                                 // for unique_ptr, make_u...
#include <mutex>                                  // for call_once, once_flag
#include <queue>                                  // for priority_queue
#include <string>                                 // for allocator, string
#include <thread>                                 // for sleep_for, thread
#include <utility>                                // for move
#include <vector>                                 // for vector

namespace quill
{
using backend_worker_error_handler_t = std::function<void(std::string const&)>;

namespace detail
{

class BackendWorker
{
public:
  /**
   * Constructor
   */
  BackendWorker(Config const& config, ThreadContextCollection& thread_context_collection,
                HandlerCollection const& handler_collection);

  /**
   * Deleted
   */
  BackendWorker(BackendWorker const&) = delete;
  BackendWorker& operator=(BackendWorker const&) = delete;

  /**
   * Destructor
   */
  ~BackendWorker();

  /**
   * Returns the status of the backend worker thread
   * @return true when the worker is running, false otherwise
   */
  QUILL_NODISCARD QUILL_ATTRIBUTE_HOT inline bool is_running() const noexcept;

  /**
   * Get the backend worker's thread id
   * @return the backend worker's thread id
   */
  QUILL_NODISCARD uint32_t thread_id() const noexcept;

  /**
   * Starts the backend worker thread
   * @throws std::runtime_error, std::system_error on failures
   */
  QUILL_ATTRIBUTE_COLD inline void run();

  /**
   * Stops the backend worker thread
   */
  QUILL_ATTRIBUTE_COLD void stop() noexcept;

#if !defined(QUILL_NO_EXCEPTIONS)
  /**
   * Set up a custom error handler that will be used if the backend thread has any error.
   * If no error handler is set, the default one will print to std::cerr
   * @param error_handler an error handler callback e.g [](std::string const& s) { std::cerr << s << std::endl; }
   * @throws exception if it is called after the thread has started
   */
  QUILL_ATTRIBUTE_COLD void set_error_handler(backend_worker_error_handler_t error_handler);
#endif

private:
  /**
   * Backend worker thread main function
   */
  QUILL_ATTRIBUTE_HOT inline void _main_loop();

  /**
   * Logging thread exist function that flushes everything after stop() is called
   */
  QUILL_ATTRIBUTE_COLD inline void _exit();

  /**
   * Populate our local priority queue
   * @param cached_thread_contexts local thread context cache
   */
  QUILL_ATTRIBUTE_HOT inline void _populate_priority_queue(
    ThreadContextCollection::backend_thread_contexts_cache_t const& cached_thread_contexts);

  /**
   * Checks for events in all queues and processes the one with the minimum timestamp
   */
  QUILL_ATTRIBUTE_HOT inline void _process_event();

  /**
   * Force flush all active Handlers
   */
  QUILL_ATTRIBUTE_HOT inline void _force_flush();

  /**
   * Convert a timestamp from BaseEvent to a time since epoch timestamp in nanoseconds.
   *
   * @param base_event The base event timestamp is just an uint64 and it can be either
   * rdtsc time or nanoseconds since epoch based on #if !defined(QUILL_CHRONO_CLOCK) definition
   * @return a timestamp in nanoseconds since epoch
   */
  QUILL_NODISCARD QUILL_ATTRIBUTE_HOT inline std::chrono::nanoseconds _get_real_timestamp(BaseEvent const* base_event) const noexcept;

  /**
   * Check for dropped messages - only when bounded queue is used
   * @param cached_thread_contexts loaded thread contexts
   */
  QUILL_ATTRIBUTE_HOT static void _check_dropped_messages(
    ThreadContextCollection::backend_thread_contexts_cache_t const& cached_thread_contexts) noexcept;

private:
  struct TransitEvent
  {
    /**
     * Constructor used when we are pulling event from the generic_queue
     * @param in_thread_context
     * @param base_event
     */
    TransitEvent(ThreadContext* in_thread_context,
                 std::unique_ptr<BaseEvent, FreeListAllocatorDeleter<BaseEvent>> in_base_event)
      : thread_context(in_thread_context),
        base_event(std::move(in_base_event)),
        timestamp(base_event->timestamp())
    {
    }

    /**
     * Constructor used for any events coming from the fast_queue
     * @param in_thread_context
     * @param in_timestamp
     * @param in_log_data_node
     * @param in_fmt_store
     */
    TransitEvent(ThreadContext* in_thread_context, uint64_t in_timestamp,
                 detail::LogDataNode const* in_log_data_node, detail::LoggerDetails const* in_logger_details,
                 fmt::dynamic_format_arg_store<fmt::format_context> in_fmt_store)
      : thread_context(in_thread_context),
        timestamp(in_timestamp),
        log_data_node(in_log_data_node),
        logger_details(in_logger_details),
        fmt_store(std::move(in_fmt_store))
    {
    }

    friend bool operator>(TransitEvent const& lhs, TransitEvent const& rhs)
    {
      return lhs.timestamp > rhs.timestamp;
    }

    ThreadContext* thread_context; /** We clean any invalidated thread_context after the priority queue is empty, so this can not be invalid */

    /**
     * TransitEvent is like a variant, it will contain a base_event is the event was pulled from the generic_queue
     * or it will contain metadata* and fmt dynamic store if the event was pulled from the fast_queue
     */
    std::unique_ptr<BaseEvent, FreeListAllocatorDeleter<BaseEvent>> base_event{nullptr};

    uint64_t timestamp;                                /** timestamp is populated for both events */
    detail::LogDataNode const* log_data_node{nullptr}; /** log_data_node in case of fast_queue **/
    detail::LoggerDetails const* logger_details{nullptr};         /** The logger details **/
    fmt::dynamic_format_arg_store<fmt::format_context> fmt_store; /** fmt_store in case of fast_queue **/
  };

private:
  Config const& _config;
  ThreadContextCollection& _thread_context_collection;
  HandlerCollection const& _handler_collection;

  std::thread _backend_worker_thread; /** the backend thread that is writing the log to the handlers */
  uint32_t _backend_worker_thread_id{0}; /** cached backend worker thread id */

  std::unique_ptr<RdtscClock> _rdtsc_clock{nullptr}; /** rdtsc clock if enabled **/

  std::chrono::nanoseconds _backend_thread_sleep_duration; /** backend_thread_sleep_duration from config **/
  std::once_flag _start_init_once_flag; /** flag to start the thread only once, in case start() is called multiple times */
  bool _has_unflushed_messages{false}; /** There are messages that are buffered by the OS, but not yet flushed */
  std::atomic<bool> _is_running{false}; /** The spawned backend thread status */
  std::priority_queue<TransitEvent, std::vector<TransitEvent>, std::greater<>> _transit_events;

  BacktraceLogRecordStorage _backtrace_log_record_storage; /** Stores a vector of backtrace log records per logger name */

  FreeListAllocator _free_list_allocator; /** A free list allocator with initial capacity, we store the TransitEvents that we pop from each SPSC queue here */

#if !defined(QUILL_NO_EXCEPTIONS)
  backend_worker_error_handler_t _error_handler; /** error handler for the backend thread */
#endif
};

/***/
bool BackendWorker::is_running() const noexcept
{
  return _is_running.load(std::memory_order_relaxed);
}

/***/
void BackendWorker::run()
{
  // protect init to be called only once
  std::call_once(_start_init_once_flag, [this]() {
    // We store the configuration here on our local variable since the config flag is not atomic
    // and we don't want it to change after we have started - This is just for safety and to
    // enforce the user to configure a variable before the thread has started
    _backend_thread_sleep_duration = _config.backend_thread_sleep_duration();

    std::thread worker([this]() {
      QUILL_TRY
      {
        // On Start
        if (_config.backend_thread_cpu_affinity() != (std::numeric_limits<uint16_t>::max()))
        {
          // Set cpu affinity if requested to cpu _backend_thread_cpu_affinity
          set_cpu_affinity(_config.backend_thread_cpu_affinity());
        }

        // Set the thread name to the desired name
        set_thread_name(_config.backend_thread_name().data());
      }
#if !defined(QUILL_NO_EXCEPTIONS)
      QUILL_CATCH(std::exception const& e) { _error_handler(e.what()); }
      QUILL_CATCH_ALL() { _error_handler(std::string{"Caught unhandled exception."}); }
#endif

#if !defined(QUILL_CHRONO_CLOCK)
      // Use rdtsc clock based on config. The clock requires a few seconds to init as it is
      // taking samples first
      _rdtsc_clock = std::make_unique<RdtscClock>(std::chrono::milliseconds{QUILL_RDTSC_RESYNC_INTERVAL});
#endif

      // Cache this thread's id
      _backend_worker_thread_id = get_thread_id();

      // Initialise memory for our free list allocator. We reserve the same size as a full
      // size of 1 caller thread queue
      _free_list_allocator.reserve(QUILL_QUEUE_CAPACITY);

      // Also configure our allocator to request bigger chunks from os
      _free_list_allocator.set_minimum_allocation(QUILL_QUEUE_CAPACITY);

      // All okay, set the backend worker thread running flag
      _is_running.store(true, std::memory_order_seq_cst);

      // Running
      while (QUILL_LIKELY(_is_running.load(std::memory_order_relaxed)))
      {
        // main loop
        QUILL_TRY { _main_loop(); }
#if !defined(QUILL_NO_EXCEPTIONS)
        QUILL_CATCH(std::exception const& e) { _error_handler(e.what()); }
        QUILL_CATCH_ALL()
        {
          _error_handler(std::string{"Caught unhandled exception."});
        } // clang-format on
#endif
      }

      // exit
      QUILL_TRY { _exit(); }
#if !defined(QUILL_NO_EXCEPTIONS)
      QUILL_CATCH(std::exception const& e) { _error_handler(e.what()); }
      QUILL_CATCH_ALL()
      {
        _error_handler(std::string{"Caught unhandled exception."});
      } // clang-format on
#endif
    });

    // Move the worker ownership to our class
    _backend_worker_thread.swap(worker);

    while (!_is_running.load(std::memory_order_seq_cst))
    {
      // wait for the thread to start
      std::this_thread::sleep_for(std::chrono::microseconds{100});
    }
  });
}

/***/
void BackendWorker::_populate_priority_queue(ThreadContextCollection::backend_thread_contexts_cache_t const& cached_thread_contexts)
{
  // copy everything to a priority queue
  for (ThreadContext* thread_context : cached_thread_contexts)
  {
    // Read the generic queue
    ThreadContext::SPSCQueueT& generic_spsc_queue = thread_context->spsc_queue();

    while (true)
    {
      auto handle = generic_spsc_queue.try_pop();

      if (!handle.is_valid())
      {
        break;
      }
      _transit_events.emplace(thread_context, handle.data()->clone(_free_list_allocator));
    }

    // Read the fast queue
    ThreadContext::FastSPSCQueueT& fast_spsc_queue = thread_context->fast_spsc_queue();

    while (true)
    {
      // Note: The producer will commit a write to this queue when one complete message is written.
      // This means that if we can read something from the queue it will be a full message
      // The producer will add items to the buffer :
      // |timestamp|log_data_node*|logger_details*|args...|

      // We want to read a minimum size of uint64_t (the size of the timestamp)
      uint64_t bytes_available;
      auto read_buffer = fast_spsc_queue.peek(&bytes_available);
      if (bytes_available == 0)
      {
        // nothing to read
        break;
      }

      // read the next full message
      auto const timestamp = *(reinterpret_cast<uint64_t const*>(read_buffer));
      read_buffer += sizeof(uint64_t);

      auto const data_node_ptr = *(reinterpret_cast<uintptr_t const*>(read_buffer));
      auto const data_node = reinterpret_cast<detail::LogDataNode const*>(data_node_ptr);
      read_buffer += sizeof(uintptr_t);

      auto const logger_details_ptr = *(reinterpret_cast<uintptr_t const*>(read_buffer));
      auto const logger_details = reinterpret_cast<detail::LoggerDetails const*>(logger_details_ptr);
      read_buffer += sizeof(uintptr_t);

      // Use our type_info string to read the remaining message until the end
      std::vector<std::string> tokens;
      std::string ext_token;
      std::istringstream token_stream(data_node->type_info_data);
      while (std::getline(token_stream, ext_token, '%'))
      {
        tokens.push_back(ext_token);
      }

      // Store all arguments
      fmt::dynamic_format_arg_store<fmt::format_context> fmt_store;
      size_t read_size = 0;
      for (auto const& token : tokens)
      {
        if (token == "I8")
        {
          using type_t = int8_t;
          fmt_store.push_back(*(reinterpret_cast<type_t const*>(read_buffer)));

          read_buffer += sizeof(type_t);
          read_size += sizeof(type_t);
        }
        else if (token == "I16")
        {
          using type_t = int16_t;
          fmt_store.push_back(*(reinterpret_cast<type_t const*>(read_buffer)));

          read_buffer += sizeof(type_t);
          read_size += sizeof(type_t);
        }
        else if (token == "I32")
        {
          using type_t = int32_t;
          fmt_store.push_back(*(reinterpret_cast<type_t const*>(read_buffer)));

          read_buffer += sizeof(type_t);
          read_size += sizeof(type_t);
        }
        else if (token == "I64")
        {
          using type_t = int64_t;
          fmt_store.push_back(*(reinterpret_cast<type_t const*>(read_buffer)));

          read_buffer += sizeof(type_t);
          read_size += sizeof(type_t);
        }
        else if (token == "U8")
        {
          using type_t = uint8_t;
          fmt_store.push_back(*(reinterpret_cast<type_t const*>(read_buffer)));

          read_buffer += sizeof(type_t);
          read_size += sizeof(type_t);
        }
        else if (token == "U16")
        {
          using type_t = uint16_t;
          fmt_store.push_back(*(reinterpret_cast<type_t const*>(read_buffer)));

          read_buffer += sizeof(type_t);
          read_size += sizeof(type_t);
        }
        else if (token == "U32")
        {
          using type_t = uint32_t;
          fmt_store.push_back(*(reinterpret_cast<type_t const*>(read_buffer)));

          read_buffer += sizeof(type_t);
          read_size += sizeof(type_t);
        }
        else if (token == "U64")
        {
          using type_t = uint64_t;
          fmt_store.push_back(*(reinterpret_cast<type_t const*>(read_buffer)));

          read_buffer += sizeof(type_t);
          read_size += sizeof(type_t);
        }
        else if (token == "D")
        {
          using type_t = double;
          fmt_store.push_back(*(reinterpret_cast<type_t const*>(read_buffer)));

          read_buffer += sizeof(type_t);
          read_size += sizeof(type_t);
        }
        else if (token == "LD")
        {
          using type_t = long double;
          fmt_store.push_back(*(reinterpret_cast<type_t const*>(read_buffer)));

          read_buffer += sizeof(type_t);
          read_size += sizeof(type_t);
        }
        else if (token == "F")
        {
          using type_t = float;
          fmt_store.push_back(*(reinterpret_cast<type_t const*>(read_buffer)));

          read_buffer += sizeof(type_t);
          read_size += sizeof(type_t);
        }
        else if (token == "C")
        {
          using type_t = char;
          fmt_store.push_back(*(reinterpret_cast<type_t const*>(read_buffer)));

          read_buffer += sizeof(type_t);
          read_size += sizeof(type_t);
        }
        else if (token == "S")
        {
          fmt_store.push_back((reinterpret_cast<char const*>(read_buffer)));

          size_t const len = strlen(reinterpret_cast<char const*>(read_buffer));
          read_buffer += len + 1;
          read_size += len + 1;
        }
      }

      // Finish reading
      fast_spsc_queue.consume(sizeof(uint64_t) + sizeof(uintptr_t) + sizeof(uintptr_t) + read_size);

      // We have the timestamp and the data node ptr, we can construct a transit event out of them
      _transit_events.emplace(thread_context, timestamp, data_node, logger_details, std::move(fmt_store));
    }
  }
}

/***/
void BackendWorker::_process_event()
{
  TransitEvent const& transit_event = _transit_events.top();

  // A lambda to obtain the logger details and pass them to backend_process(...), this lambda is
  // called only in case we need to flush because we are processing a FlushEvent
  auto obtain_active_handlers = [this]() { return _handler_collection.active_handlers(); };

  // This lambda will call our member function _get_real_timestamp
  auto get_real_ts = [this](BaseEvent const* base_event) { return _get_real_timestamp(base_event); };

  // If backend_process(...) throws we want to skip this event and move to the next so we catch the
  // error here instead of catching it in the parent try/catch block of main_loop
  QUILL_TRY
  {
    if (transit_event.base_event)
    {
      // This is a transit event coming from the generic_spsc_event_queue
      transit_event.base_event->backend_process(_backtrace_log_record_storage,
                                                transit_event.thread_context->thread_id(),
                                                obtain_active_handlers, get_real_ts);
    }
    else
    {
      // We are processing a transit event coming from the fast_spsc_event_queue
      // Forward the record to all of the logger handlers
      for (auto& handler : transit_event.logger_details->handlers())
      {

#if !defined(QUILL_CHRONO_CLOCK)
        std::chrono::nanoseconds const timestamp = _rdtsc_clock->time_since_epoch(transit_event.timestamp);
#else
        // Then the timestamp() will be already in epoch no need to convert it like above
        // The precision of system_clock::time-point is not portable across platforms.
        std::chrono::system_clock::duration const timestamp_duration{transit_event.timestamp};
        std::chrono::nanoseconds const timestamp = std::chrono::nanoseconds{timestamp_duration};
#endif
        handler->formatter().format(timestamp, transit_event.thread_context->thread_id(),
                                    transit_event.logger_details->name(),
                                    transit_event.log_data_node->metadata, transit_event.fmt_store);

        // After calling format on the formatter we have to request the formatter record
        auto const& formatted_log_record_buffer = handler->formatter().formatted_log_record();

        // If all filters are okay we write this log record to the file
        if (handler->apply_filters(transit_event.thread_context->thread_id(), timestamp,
                                   transit_event.log_data_node->metadata, formatted_log_record_buffer))
        {
          // log to the handler, also pass the log_record_timestamp this is only needed in some
          // cases like daily file rotation
          handler->write(formatted_log_record_buffer, timestamp,
                         transit_event.log_data_node->metadata.level());
        }
      }
    }

    // Remove this event and move to the next
    _transit_events.pop();

    // Since after processing an event we never force flush but leave it up to the OS instead,
    // set this to true to keep track of unflushed messages we have
    _has_unflushed_messages = true;
  }
#if !defined(QUILL_NO_EXCEPTIONS)
  QUILL_CATCH(std::exception const& e)
  {
    _error_handler(e.what());

    // Remove this event and move to the next
    _transit_events.pop();
  }
  QUILL_CATCH_ALL()
  {
    _error_handler(std::string{"Caught unhandled exception."});

    // Remove this event and move to the next
    _transit_events.pop();
  } // clang-format on
#endif
}

void BackendWorker::_force_flush()
{
  if (_has_unflushed_messages)
  {
    // If we have buffered any messages then get all active handlers and call flush
    std::vector<Handler*> const active_handlers = _handler_collection.active_handlers();
    for (auto handler : active_handlers)
    {
      handler->flush();
    }

    _has_unflushed_messages = false;
  }
}

/***/
void BackendWorker::_main_loop()
{
  // load all contexts locally
  ThreadContextCollection::backend_thread_contexts_cache_t const& cached_thread_contexts =
    _thread_context_collection.backend_thread_contexts_cache();

  _populate_priority_queue(cached_thread_contexts);

  if (QUILL_LIKELY(!_transit_events.empty()))
  {
    // the queue is not empty
    _process_event();
  }
  else
  {
    // there was nothing to process

    // None of the thread local queues had any events to process, this means we have processed
    // all messages in all queues We will force flush any unflushed messages and then sleep
    _force_flush();

    // check for any dropped messages by the threads
    _check_dropped_messages(cached_thread_contexts);

    // We can also clear any invalidated or empty thread contexts now that our priority queue was empty
    _thread_context_collection.clear_invalid_and_empty_thread_contexts();

    // Sleep for the specified duration as we found no events in any of the queues to process
    std::this_thread::sleep_for(_backend_thread_sleep_duration);
  }
}

/***/
std::chrono::nanoseconds BackendWorker::_get_real_timestamp(BaseEvent const* base_event) const noexcept
{
#if !defined(QUILL_CHRONO_CLOCK)
  static_assert(
    std::is_same<BaseEvent::using_rdtsc, std::true_type>::value,
    "BaseEvent has a std::chrono timestamp, but the backend thread is using rdtsc timestamp");
  // pass to our clock the stored rdtsc from the caller thread
  return _rdtsc_clock->time_since_epoch(base_event->timestamp());
#else
  static_assert(
    std::is_same<BaseEvent::using_rdtsc, std::false_type>::value,
    "BaseEvent has an rdtsc timestamp, but the backend thread is using std::chrono timestamp");

  // Then the timestamp() will be already in epoch no need to convert it like above
  // The precision of system_clock::time-point is not portable across platforms.
  std::chrono::system_clock::duration const timestamp_duration{base_event->timestamp()};
  return std::chrono::nanoseconds{timestamp_duration};
#endif
}

/***/
void BackendWorker::_exit()
{
  // load all contexts locally
  ThreadContextCollection::backend_thread_contexts_cache_t const& cached_thread_contexts =
    _thread_context_collection.backend_thread_contexts_cache();

  while (true)
  {
    _populate_priority_queue(cached_thread_contexts);

    if (!_transit_events.empty())
    {
      _process_event();
    }
    else
    {
      _check_dropped_messages(cached_thread_contexts);

      // keep going until there are no events are found
      break;
    }
  }
}
} // namespace detail
} // namespace quill