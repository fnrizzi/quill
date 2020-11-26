/**
 * Copyright(c) 2020-present, Odysseas Georgoudis & quill contributors.
 * Distributed under the MIT License (http://opensource.org/licenses/MIT)
 */

#pragma once

#include "quill/detail/BoundedSPSCObjectQueue.h"
#include <atomic>
#include <cassert>
#include <cstddef>
#include <iostream>

namespace quill
{
namespace detail
{

/**
 * A singe-producer single-consumer FIFO circular buffer
 *
 * The buffer allows producing and consuming objects
 * The object type has to be provided as a template parameter
 *
 * Production is wait free. When the internal circlular buffer becomes full
 * a new one will be created and the production will continue in the new buffer.
 *
 * Consumption is wait free. If not data is available a special value is returned. If a new
 * buffer is created from the producer the consumer first consumes everything in the old
 * buffer and then moves to the new buffer.
 *
 * The old buffer is not used anymore when it becomes empty once.
 *
 * A grow factor of 1.5 is used.
 *
 * @note This class has a slight performance penalty compared to the fixed_circular_buffer
 *       version but it offers extra safety. When performance is important consider using a
 *       large fixed_circular_buffer instead.
 */
template <typename TBaseObject, size_t Capacity>
class UnboundedSPSCObjectQueue
{
public:
  using value_type = TBaseObject;
  using bounded_spsc_queue_t = BoundedSPSCObjectQueue<value_type, Capacity>;
  using handle_t = typename bounded_spsc_queue_t::Handle;

private:
  /** Private Definitions **/

  /**
   * A node has a buffer and a pointer to the next node
   */
  struct alignas(CACHELINE_SIZE) node
  {
    /**
     * Constructor
     * @param capacity the capacity of the fixed buffer
     */
    explicit node() = default;

    /**
     * Alignment requirement as we have bounded_spsc_queue as member
     * @param i
     * @return
     */
    void* operator new(size_t i) { return aligned_alloc(CACHELINE_SIZE, i); }
    void operator delete(void* p) { aligned_free(p); }

    /** members */
    bounded_spsc_queue_t bounded_spsc_queue;
    alignas(CACHELINE_SIZE) std::atomic<node*> next{nullptr};
    char _pad1[detail::CACHELINE_SIZE - sizeof(std::atomic<node*>)];
  };

public:
  /**
   * Constructor
   * @param capacity The starting capacity
   */
  explicit UnboundedSPSCObjectQueue() : _producer(new node()), _consumer(_producer) {}

  /**
   * Deleted
   */
  UnboundedSPSCObjectQueue(UnboundedSPSCObjectQueue const&) = delete;
  UnboundedSPSCObjectQueue& operator=(UnboundedSPSCObjectQueue const&) = delete;

  /**
   * Destructor
   */
  ~UnboundedSPSCObjectQueue()
  {
    // Get the current consumer node
    node* current_node = _consumer;

    // Look for extra nodes to delete
    while (current_node != nullptr)
    {
      auto to_delete = current_node;
      current_node = current_node->next;
      delete to_delete;
    }
  }

  /**
   * Push an item to the circular buffer
   * This function will never block but if the underlying buffer is full we will need to
   * allocate a new one
   * @param item The item to insert
   */
  template <typename TInsertedObject, typename... Args>
  QUILL_ALWAYS_INLINE_HOT void emplace(Args&&... args) noexcept
  {
    // Try to emplace to the bounded queue
    if (QUILL_UNLIKELY(!_producer->bounded_spsc_queue.template try_emplace<TInsertedObject>(
          std::forward<Args>(args)...)))
    {
      // We failed to emplace because the queue was full, create a new node with the a new queue
      auto next_node = new node{};

      // store the new node pointer as next in the current node
      _producer->next.store(next_node, std::memory_order_release);

      // producer is now using the next node
      _producer = next_node;

      // add the item again, this time we know we will always succeed, cast to void* to ignore
      QUILL_MAYBE_UNUSED bool const emplaced_ =
        _producer->bounded_spsc_queue.template try_emplace<TInsertedObject>(std::forward<Args>(args)...);
    }
  }

  /**
   * Return a handle containing a handle to an object
   * @return a handle to the object we read from the queue
   */
  QUILL_NODISCARD QUILL_NODISCARD_ALWAYS_INLINE_HOT handle_t try_pop() noexcept
  {
    handle_t obj_handle = _consumer->bounded_spsc_queue.try_pop();

    if (!obj_handle.is_valid())
    {
      // the buffer is empty check if another buffer exists
      node* const next_node = _consumer->next.load(std::memory_order_acquire);

      if (QUILL_UNLIKELY(next_node != nullptr))
      {
        // a new buffer was added by the producer, this happens only when we have allocated a new queue

        // try the existing buffer once more
        obj_handle = _consumer->bounded_spsc_queue.try_pop();

        if (!obj_handle.is_valid())
        {
          // switch to the new buffer, existing one is deleted
          delete _consumer;
          _consumer = next_node;
          obj_handle = _consumer->bounded_spsc_queue.try_pop();
        }
      }
    }
    return obj_handle;
  }

  /**
   * Used if instead of pushing an object we want to get the raw memory inside the buffer to
   * write the object ourselves.
   * This is used for POD only types to directly memcpy them inside the buffer
   * @note: has to be used along with commit_write
   * @param requested_size the size we want to copy
   * @return Buffer begin to write the object
   */
  QUILL_NODISCARD_ALWAYS_INLINE_HOT unsigned char* prepare_write(size_t requested_size) noexcept
  {
    unsigned char* write_buffer = _producer->bounded_spsc_queue.prepare_write(requested_size);

    // Try to prepare write to the bounded queue
    if (QUILL_UNLIKELY(!write_buffer))
    {
      // We failed to get the buffer because the queue was full, create a new node with the a new queue
      auto next_node = new node{};

      // store the new node pointer as next in the current node
      _producer->next.store(next_node, std::memory_order_release);

      // producer is now using the next node
      _producer = next_node;

      // add the item again, this time we know we will always succeed, cast to void* to ignore
      write_buffer = _producer->bounded_spsc_queue.prepare_write(requested_size);
    }

    return write_buffer;
  }

  /**
   * Must be called after prepare_write to commit the write to the buffer and make the consumer
   * thread aware of the write
   * @note: must be used after prepare_write
   * @param requested_size size of bytes we wrote to the buffer
   */
  QUILL_NODISCARD_ALWAYS_INLINE_HOT void commit_write(size_t requested_size) noexcept
  {
    _producer->bounded_spsc_queue.commit_write(requested_size);
  }

  /**
   * Used to read the raw buffer directly. This is used only when we push PODs
   * @return nullptr if nothing to read, else the location of the buffer to read
   *    * @param min_size minimum size to read
   */
  QUILL_NODISCARD_ALWAYS_INLINE_HOT unsigned const char* prepare_read(size_t min_size) noexcept
  {
    unsigned const char* read_buffer = _consumer->bounded_spsc_queue.prepare_read(min_size);

    if (!read_buffer)
    {
      // the buffer is empty check if another buffer exists
      node* const next_node = _consumer->next.load(std::memory_order_acquire);

      if (QUILL_UNLIKELY(next_node != nullptr))
      {
        // a new buffer was added by the producer, this happens only when we have allocated a new queue

        // try the existing buffer once more
        read_buffer = _consumer->bounded_spsc_queue.prepare_read(min_size);

        if (!read_buffer)
        {
          // switch to the new buffer, existing one is deleted
          delete _consumer;
          _consumer = next_node;
          read_buffer = _consumer->bounded_spsc_queue.prepare_read(min_size);
        }
      }
    }

    return read_buffer;
  }

  /**
   * This must be called after reading bytes from the buffer with prepare_read
   * @param read_size the size we read from the buffer
   */
  QUILL_NODISCARD_ALWAYS_INLINE_HOT void finish_read(size_t read_size) noexcept
  {
    _consumer->bounded_spsc_queue.finish_read(read_size);
  }

  /**
   * Return the current buffer's capacity
   * @return
   */
  QUILL_NODISCARD QUILL_ATTRIBUTE_COLD std::size_t capacity() const noexcept
  {
    return _producer->bounded_spsc_queue.capacity();
  }

  /**
   * checks if the queue is empty
   * @return
   */
  QUILL_NODISCARD QUILL_ATTRIBUTE_COLD bool empty() noexcept
  {
    auto obj_handle = try_pop();

    if (!obj_handle.is_valid())
    {
      // nothing to pop the queue is empty
      return true;
    }

    // else there is data to push, we need to release the handle before returning so we don't consume them
    obj_handle.release();
    return false;
  }

private:
  /** Modified by either the producer or consumer but never both */
  alignas(CACHELINE_SIZE) node* _producer{nullptr};
  alignas(CACHELINE_SIZE) node* _consumer{nullptr};
  char _pad0[detail::CACHELINE_SIZE - sizeof(node*)] = "\0";
};

} // namespace detail
} // namespace quill