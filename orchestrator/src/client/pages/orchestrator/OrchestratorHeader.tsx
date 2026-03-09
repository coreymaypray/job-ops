import { PageHeader, StatusIndicator } from "@client/components/layout";
import { SlothLogo } from "@client/components/SlothLogo";
import type { JobSource } from "@shared/types.js";
import { Loader2, Play, Square } from "lucide-react";
import type React from "react";
import { Button } from "@/components/ui/button";

interface OrchestratorHeaderProps {
  navOpen: boolean;
  onNavOpenChange: (open: boolean) => void;
  isPipelineRunning: boolean;
  isCancelling: boolean;
  pipelineSources: JobSource[];
  onOpenAutomaticRun: () => void;
  onCancelPipeline: () => void;
}

export const OrchestratorHeader: React.FC<OrchestratorHeaderProps> = ({
  navOpen,
  onNavOpenChange,
  isPipelineRunning,
  isCancelling,
  pipelineSources,
  onOpenAutomaticRun,
  onCancelPipeline,
}) => {
  const actions = isPipelineRunning ? (
    <Button
      size="sm"
      onClick={onCancelPipeline}
      disabled={isCancelling}
      variant="destructive"
      className="gap-2"
    >
      {isCancelling ? (
        <Loader2 className="h-4 w-4 animate-spin" />
      ) : (
        <Square className="h-4 w-4" />
      )}
      <span className="hidden sm:inline">
        {isCancelling ? `Cancelling (${pipelineSources.length})` : `Cancel run`}
      </span>
    </Button>
  ) : (
    <Button size="sm" onClick={onOpenAutomaticRun} className="gap-2">
      <Play className="h-4 w-4" />
      <span className="hidden sm:inline">Run pipeline</span>
    </Button>
  );

  return (
    <PageHeader
      icon={() => <SlothLogo className="size-6" />}
      title="Sloth Jobs"
      subtitle="Slow & steady wins the hunt"
      navOpen={navOpen}
      onNavOpenChange={onNavOpenChange}
      statusIndicator={
        isPipelineRunning ? (
          <StatusIndicator label="Pipeline running" variant="amber" />
        ) : undefined
      }
      actions={actions}
    />
  );
};
