import { useCallback, useEffect, useState } from "react";

interface ReloadOptions {
  silent?: boolean;
}

export function useAsyncData<T>(loader: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reloadWithResult = useCallback(async (options: ReloadOptions = {}): Promise<T | null> => {
    if (!options.silent) {
      setLoading(true);
    }
    setError(null);
    try {
      const result = await loader();
      setData(result);
      return result;
    } catch (err) {
      setError(err instanceof Error ? err.message : "请求失败");
      return null;
    } finally {
      if (!options.silent) {
        setLoading(false);
      }
    }
  }, deps);

  const reload = useCallback(async (): Promise<void> => {
    await reloadWithResult();
  }, [reloadWithResult]);

  useEffect(() => {
    void reload();
  }, [reload]);

  return { data, loading, error, reload, reloadWithResult };
}
