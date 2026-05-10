import { useEffect } from "react";
import { Shell } from "./layout/Shell";
import { useAppStore } from "./store/app";

export function App() {
  const refresh = useAppStore((s) => s.refresh);
  useEffect(() => {
    void refresh();
  }, [refresh]);
  return <Shell />;
}
