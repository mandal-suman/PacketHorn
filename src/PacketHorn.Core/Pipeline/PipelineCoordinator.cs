using System;
using System.Threading;

namespace PacketHorn.Core.Pipeline;

public class PipelineCoordinator
{
    private readonly PacketPipeline _pipeline;
    private Thread? _workerThread;
    private bool _isRunning;

    public PipelineCoordinator(PacketPipeline pipeline)
    {
        _pipeline = pipeline;
    }

    public void Start()
    {
        _isRunning = true;
        _pipeline.Start();

        _workerThread = new Thread(WorkerLoop)
        {
            IsBackground = true,
            Name = "PipelineWorker"
        };
        _workerThread.Start();
    }

    public void Stop()
    {
        _isRunning = false;
        _pipeline.Stop();
        
        if (_workerThread != null && _workerThread.IsAlive)
        {
            _workerThread.Join(TimeSpan.FromSeconds(2));
        }
    }

    private void WorkerLoop()
    {
        while (_isRunning)
        {
            try
            {
                _pipeline.ProcessNextPacket();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WorkerLoop Error] {ex.Message}");
            }
        }
    }
}
