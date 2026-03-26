import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { CheckCircle2, Loader2, ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";

const STEPS = [
  "Fetching SSL Certificate...",
  "Reading WHOIS Records...",
  "Analyzing Page Content...",
  "Checking for Scam Keywords...",
  "Calculating Trust Score..."
];

interface StepLoaderProps {
  isActive: boolean;
  onComplete?: () => void;
}

export function StepLoader({ isActive, onComplete }: StepLoaderProps) {
  const [currentStep, setCurrentStep] = useState(-1);

  useEffect(() => {
    if (!isActive) {
      setCurrentStep(-1);
      return;
    }

    let isMounted = true;
    
    const runSteps = async () => {
      for (let i = 0; i < STEPS.length; i++) {
        if (!isMounted) return;
        setCurrentStep(i);
        // Varying times to make it feel real (800ms to 1500ms)
        const delay = Math.random() * 700 + 800; 
        await new Promise(r => setTimeout(r, delay));
      }
      
      if (isMounted) {
        setCurrentStep(STEPS.length); // All done
        await new Promise(r => setTimeout(r, 600)); // Brief pause before completion
        onComplete?.();
      }
    };

    runSteps();

    return () => { isMounted = false; };
  }, [isActive, onComplete]);

  if (!isActive) return null;

  return (
    <div className="w-full max-w-md mx-auto space-y-6 glass-panel p-8 rounded-3xl">
      <div className="flex items-center justify-center mb-8">
        <div className="relative">
          <ShieldCheck className="w-16 h-16 text-primary/50" />
          <motion.div 
            className="absolute inset-0 text-primary"
            animate={{ scale: [1, 1.1, 1], opacity: [0.5, 1, 0.5] }}
            transition={{ repeat: Infinity, duration: 2 }}
          >
            <ShieldCheck className="w-16 h-16" />
          </motion.div>
        </div>
      </div>

      <div className="space-y-4">
        {STEPS.map((step, index) => {
          const isPending = index > currentStep;
          const isActive = index === currentStep;
          const isDone = index < currentStep;

          return (
            <motion.div
              key={step}
              initial={{ opacity: 0, x: -20 }}
              animate={{ 
                opacity: isPending ? 0.3 : 1, 
                x: 0,
                scale: isActive ? 1.02 : 1
              }}
              transition={{ duration: 0.3 }}
              className={cn(
                "flex items-center gap-4 p-3 rounded-xl transition-colors",
                isActive ? "bg-primary/10 border border-primary/20" : "bg-transparent border border-transparent"
              )}
            >
              <div className="flex-shrink-0 w-6 h-6 flex items-center justify-center">
                <AnimatePresence mode="wait">
                  {isDone ? (
                    <motion.div
                      key="done"
                      initial={{ scale: 0 }}
                      animate={{ scale: 1 }}
                      className="text-success"
                    >
                      <CheckCircle2 className="w-6 h-6" />
                    </motion.div>
                  ) : isActive ? (
                    <motion.div
                      key="active"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      className="text-primary"
                    >
                      <Loader2 className="w-5 h-5 animate-spin" />
                    </motion.div>
                  ) : (
                    <div key="pending" className="w-3 h-3 rounded-full bg-muted" />
                  )}
                </AnimatePresence>
              </div>
              <span className={cn(
                "font-medium text-sm md:text-base",
                isActive ? "text-primary" : isDone ? "text-foreground" : "text-muted-foreground"
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
