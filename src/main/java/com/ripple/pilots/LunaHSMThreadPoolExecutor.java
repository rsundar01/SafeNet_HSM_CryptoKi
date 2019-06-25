package com.ripple.pilots;

import java.util.concurrent.*;

public class LunaHSMThreadPoolExecutor extends ThreadPoolExecutor {

    public LunaHSMThreadPoolExecutor(int corePoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit timeUnit,
          BlockingQueue<Runnable> workQueue, ThreadFactory threadFactory, RejectedExecutionHandler rejectedExecutionHandler)
    {
        super(corePoolSize, maximumPoolSize, keepAliveTime, timeUnit, workQueue, threadFactory, rejectedExecutionHandler);
    }

    public LunaHSMThreadPoolExecutor(int corePoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit timeUnit,
                                     BlockingQueue<Runnable> workQueue, ThreadFactory threadFactory)
    {
        super(corePoolSize, maximumPoolSize, keepAliveTime, timeUnit, workQueue, threadFactory);
    }

    public LunaHSMThreadPoolExecutor(int corePoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit timeUnit,
                                     BlockingQueue<Runnable> workQueue, RejectedExecutionHandler rejectedExecutionHandler)
    {
        super(corePoolSize, maximumPoolSize, keepAliveTime, timeUnit, workQueue, rejectedExecutionHandler);
    }

    public LunaHSMThreadPoolExecutor(int corePoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit timeUnit,
                                     BlockingQueue<Runnable> workQueue)
    {
        super(corePoolSize, maximumPoolSize, keepAliveTime, timeUnit, workQueue);
    }

    public static LunaHSMThreadPoolExecutor newFixedThreadPool(int nThreads) {
        return new LunaHSMThreadPoolExecutor(nThreads, nThreads, 0L, TimeUnit.MILLISECONDS,
                                                                              new LinkedBlockingQueue<Runnable>());
    }

    @Override
    protected void afterExecute(Runnable r, Throwable t){
        super.afterExecute(r, t);
    }

}
