import { SlothLogo } from "@client/components/SlothLogo";
import type React from "react";

export const EmptyState: React.FC = () => {
  return (
    <div className="flex h-full min-h-[300px] flex-col items-center justify-center gap-2 text-center px-4">
      <SlothLogo className="h-10 w-10" />
      <div className="text-sm font-medium text-muted-foreground">
        No job selected
      </div>
      <p className="text-xs text-muted-foreground/70 max-w-[200px]">
        Take your time. Select a job from the list to see details and decide whether to tailor.
      </p>
    </div>
  );
};
