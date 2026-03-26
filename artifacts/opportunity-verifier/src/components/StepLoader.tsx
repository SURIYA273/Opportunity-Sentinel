import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { CheckCircle2, Loader2, ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";

interface StepLoaderProps {
  isActive: boolean;
  steps: string[];
  onComplete?: () => void;
}

export function StepLoader({ isActive, steps, onComplete }: StepLoaderProps) {
  const [currentStep, setCurrentStep] = useState(-1);

  useEffect(() => {
    if (!isActive) {
      setCurrentStep(-1);
      return;
    }

    let isMounted = true;
    
    const runSteps = async () => {
      for (let i = 0; i < steps.length; i++) {
        if (!isMounted) return;
        setCurrentStep(i);
        // Varying times to make it feel real (800ms to 1800ms)
        const delay = Math.random() * 1000 + 800; 
        await new Promise(r => setTimeout(r, delay));
      }
      
      if (isMounted) {
        setCurrentStep(steps.length); // All done
        await new Promise(r => setTimeout(r, 600)); // Brief pause before completion
        onComplete?.();
      }
    };

    runSteps();

    return () => { isMounted = false; };
  }, [isActive, steps, onComplete]);

  if (!isActive) return null;

  return (
    <div className="w-full max-w-lg mx-auto space-y-6 glass-panel p-8 md:p-10 rounded-3xl">
      <div className="flex items-center justify-center mb-8">
        <div className="relative">
          <ShieldCheck className="w-16 h-16 text-primary/30" />
          <motion.div 
            className="absolute inset-0 text-primary"
            animate={{ scale: [1, 1.15, 1], opacity: [0.5, 1, 0.5] }}
            transition={{ repeat: Infinity, duration: 2, ease: "easeInOut" }}
          >
            <ShieldCheck className="w-16 h-16" />
          </motion.div>
        </div>
      </div>

      <div className="space-y-4">
        {steps.map((step, index) => {
          const isPending = index > currentStep;
          const isCurrentlyActive = index === currentStep;
          const isDone = index < currentStep;

          return (
            <motion.div
              key={step}
              initial={{ opacity: 0, x: -20 }}
              animate={{ 
                opacity: isPending ? 0.3 : 1, 
                x: 0,
                scale: isCurrentlyActive ? 1.02 : 1
              }}
              transition={{ duration: 0.3 }}
              className={cn(
                "flex items-center gap-4 p-4 rounded-xl transition-all duration-300",
                isCurrentlyActive ? "bg-primary/10 border border-primary/30 shadow-[0_0_15px_rgba(59,130,246,0.15)]" : "bg-transparent border border-transparent"
              )}
            >
              <div className="flex-shrink-0 w-6 h-6 flex items-center justify-center">
                <AnimatePresence mode="wait">
                  {isDone ? (
                    <motion.div
                      key="done"
                      initial={{ scale: 0 }}
                      animate={{ scale: 1 }}
                      className="text-emerald-400"
                    >
                      <CheckCircle2 className="w-6 h-6" />
                    </motion.div>
                  ) : isCurrentlyActive ? (
                    <motion.div
                      key="active"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      className="text-primary"
                    >
                      <Loader2 className="w-5 h-5 animate-spin" />
                    </motion.div>
                  ) : (
                    <div key="pending" className="w-2.5 h-2.5 rounded-full bg-muted/60" />
                  )}
                </AnimatePresence>
              </div>
              <span className={cn(
                "font-medium text-sm md:text-base tracking-wide",
                isCurrentlyActive ? "text-primary" : isDone ? "text-foreground" : "text-muted-foreground"
              )}>
                {step}
              </span>
            </motion.div>
          );
        })}
      </div>
    </div>
  );
}
