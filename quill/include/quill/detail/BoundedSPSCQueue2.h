#include <cassert>
#include <cstdint>
#include <cstring>

#define STAGING_BUFFER_SIZE 1'048'576

/**
 * This method creates a boundary across which load instructions cannot
 * migrate: if a memory read comes from code occurring before (after)
 * invoking this method, the read is guaranteed to complete before (after)
 * the method is invoked.
 */
static void inline lfence() { __asm__ __volatile__("lfence" ::: "memory"); }

/**
 * This method creates a boundary across which store instructions cannot
 * migrate: if a memory store comes from code occurring before (after)
 * invoking this method, the store is guaranteed to complete before (after)
 * the method is invoked.
 */
static void inline sfence() { __asm__ __volatile__("sfence" ::: "memory"); }

/**
 * Implements a circular FIFO producer/consumer byte queue that is used
 * to hold the dynamic information of a   log statement (producer)
 * as it waits for compression via the   background thread
 * (consumer). There exists a StagingBuffer for every thread that uses
 * the   system.
 */
class StagingBuffer
{
public:
  /**
   * Attempt to reserve contiguous space for the producer without
   * making it visible to the consumer. The caller should invoke
   * finishReservation() before invoking reserveProducerSpace()
   * again to make the bytes reserved visible to the consumer.
   *
   * This mechanism is in place to allow the producer to initialize
   * the contents of the reservation before exposing it to the
   * consumer. This function will block behind the consumer if
   * there's not enough space.
   *
   * \param nbytes
   *      Number of bytes to allocate
   *
   * \return
   *      Pointer to at least nbytes of contiguous space
   */
  inline char* reserveProducerSpace(size_t nbytes)
  {

    // Fast in-line path
    if (nbytes < minFreeSpace)
      return producerPos;

    // Slow allocation
    return reserveSpaceInternal(nbytes);
  }

  /**
   * Complement to reserveProducerSpace that makes nbytes starting
   * from the return of reserveProducerSpace visible to the consumer.
   *
   * \param nbytes
   *      Number of bytes to expose to the consumer
   */
  inline void finishReservation(size_t nbytes)
  {
    assert(nbytes < minFreeSpace);
    assert(producerPos + nbytes < storage + STAGING_BUFFER_SIZE);

    sfence(); // Ensures producer finishes writes before bump
    minFreeSpace -= nbytes;
    producerPos += nbytes;
  }

  char* peek(uint64_t* bytesAvailable)
  {
    // Save a consistent copy of producerPos
    char* cachedProducerPos = producerPos;

    if (cachedProducerPos < consumerPos)
    {
      lfence(); // Prevent reading new producerPos but old endOf...
      *bytesAvailable = endOfRecordedSpace - consumerPos;

      if (*bytesAvailable > 0)
        return consumerPos;

      // Roll over
      consumerPos = storage;
    }

    *bytesAvailable = cachedProducerPos - consumerPos;
    return consumerPos;
  }

  /**
   * Consumes the next nbytes in the StagingBuffer and frees it back
   * for the producer to reuse. nbytes must be less than what is
   * returned by peek().
   *
   * \param nbytes
   *      Number of bytes to return back to the producer
   */
  inline void consume(uint64_t nbytes)
  {
    lfence(); // Make sure consumer reads finish before bump
    consumerPos += nbytes;
  }

  /**
   * Returns true if it's safe for the compression thread to delete
   * the StagingBuffer and remove it from the global vector.
   *
   * \return
   *      true if its safe to delete the StagingBuffer
   */
  bool checkCanDelete() { return shouldDeallocate && consumerPos == producerPos; }

  StagingBuffer()
    : producerPos(storage),
      endOfRecordedSpace(storage + STAGING_BUFFER_SIZE),
      minFreeSpace(STAGING_BUFFER_SIZE),
      cacheLineSpacer(),
      consumerPos(storage),
      shouldDeallocate(false),
      storage()
  {
  }

  ~StagingBuffer() {}

private:
  char* reserveSpaceInternal(size_t nbytes, bool blocking = true)
  {
    const char* endOfBuffer = storage + STAGING_BUFFER_SIZE;

    // There's a subtle point here, all the checks for remaining
    // space are strictly < or >, not <= or => because if we allow
    // the record and print positions to overlap, we can't tell
    // if the buffer either completely full or completely empty.
    // Doing this check here ensures that == means completely empty.
    while (minFreeSpace <= nbytes)
    {
      // Since consumerPos can be updated in a different thread, we
      // save a consistent copy of it here to do calculations on
      char* cachedConsumerPos = consumerPos;

      if (cachedConsumerPos <= producerPos)
      {
        minFreeSpace = endOfBuffer - producerPos;

        if (minFreeSpace > nbytes)
          break;

        // Not enough space at the end of the buffer; wrap around
        endOfRecordedSpace = producerPos;

        // Prevent the roll over if it overlaps the two positions because
        // that would imply the buffer is completely empty when it's not.
        if (cachedConsumerPos != storage)
        {
          // prevents producerPos from updating before endOfRecordedSpace
          sfence();
          producerPos = storage;
          minFreeSpace = cachedConsumerPos - producerPos;
        }
      }
      else
      {
        minFreeSpace = cachedConsumerPos - producerPos;
      }

      // Needed to prevent infinite loops in tests
      if (!blocking && minFreeSpace <= nbytes)
        return nullptr;
    }
    return producerPos;
  }

  // Position within storage[] where the producer may place new data
  char* producerPos;

  // Marks the end of valid data for the consumer. Set by the producer
  // on a roll-over
  char* endOfRecordedSpace;

  // Lower bound on the number of bytes the producer can allocate w/o
  // rolling over the producerPos or stalling behind the consumer
  uint64_t minFreeSpace;

  // An extra cache-line to separate the variables that are primarily
  // updated/read by the producer (above) from the ones by the
  // consumer(below)
  char cacheLineSpacer[2 * 64];

  // Position within the storage buffer where the consumer will consume
  // the next bytes from. This value is only updated by the consumer.
  char* volatile consumerPos;

  // Indicates that the thread owning this StagingBuffer has been
  // destructed (i.e. no more messages will be logged to it) and thus
  // should be cleaned up once the buffer has been emptied by the
  // compression thread.
  bool shouldDeallocate;

  // Backing store used to implement the circular queue
  char storage[STAGING_BUFFER_SIZE];
};