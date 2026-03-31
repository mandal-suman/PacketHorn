using System.Collections.Concurrent;

namespace PacketHorn.Core.Utilities;

public class BufferQueue<T>
{
    private readonly BlockingCollection<T> _queue;

    public BufferQueue(int boundedCapacity)
    {
        _queue = new BlockingCollection<T>(boundedCapacity);
    }

    public void Enqueue(T item)
    {
        _queue.Add(item);
    }

    public T Take()
    {
        return _queue.Take();
    }

    public bool TryTake(out T item, int millisecondsTimeout = -1)
    {
        return _queue.TryTake(out item, millisecondsTimeout);
    }

    public void CompleteAdding()
    {
        _queue.CompleteAdding();
    }

    public bool IsCompleted => _queue.IsCompleted;
}
