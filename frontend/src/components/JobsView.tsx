import { useEffect, useState } from "react";
import { api } from "../lib/api";

export function JobsView() {
  const [jobs, setJobs] = useState<Record<string, string>>({});

  const refresh = () => api.jobs.list().then(setJobs);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 5000);
    return () => clearInterval(t);
  }, []);

  const entries = Object.entries(jobs);

  return (
    <div className="p-4">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-sm text-gray-200">Running Jobs</h2>
        <button onClick={refresh} className="text-xs text-gray-500 hover:text-gray-300">
          refresh
        </button>
      </div>
      {entries.length === 0 && <div className="text-xs text-gray-600">No running jobs.</div>}
      {entries.length > 0 && (
        <table className="w-full text-xs font-mono">
          <thead>
            <tr className="text-left text-gray-500 border-b border-border">
              <th className="py-1.5 pr-4">ID</th>
              <th className="py-1.5 pr-4">Name</th>
              <th className="py-1.5"></th>
            </tr>
          </thead>
          <tbody>
            {entries.map(([id, name]) => (
              <tr key={id} className="border-b border-border/50 text-gray-300">
                <td className="py-1.5 pr-4 text-accent">{id}</td>
                <td className="py-1.5 pr-4">{name}</td>
                <td className="py-1.5">
                  <button
                    onClick={() => api.jobs.stop(id).then(refresh)}
                    className="text-danger hover:underline"
                  >
                    stop
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
