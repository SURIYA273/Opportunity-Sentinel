import { motion, AnimatePresence } from "framer-motion";
import { Gauge } from "./Gauge";
import {
  ShieldCheck, AlertTriangle, Info, CheckCircle2, RefreshCw,
  XCircle, ChevronDown, ChevronUp, Phone, Mail, Link2,
  DollarSign, ArrowRight, Zap, AlertCircle
} from "lucide-react";
import { cn, getGradeColorClass } from "@/lib/utils";
import { useState } from "react";

export interface NextStep {
  priority: "critical" | "high" | "medium" | "low";
  action: string;
  detail: string;
}

export interface Entities {
  phones?: string[];
  emails?: string[];
  urls?: string[];
  money?: string[];
}

export interface UnifiedResult {
  trustScore: number;
  grade: string;
  flags: {
    category: string;
    severity: "low" | "medium" | "high";
    message: string;
  }[];
  summary: string;
  extractedText?: string | null;
  url?: string;
  inputType?: string;
  nextSteps?: NextStep[];
  entities?: Entities;
}

interface VerdictCardProps {
  result: UnifiedResult;
  onReset: () => void;
}

const priorityConfig = {
  critical: { color: "text-destructive", bg: "bg-destructive/10 border-destructive/30", icon: XCircle, label: "Critical" },
  high:     { color: "text-orange-400",  bg: "bg-orange-500/10 border-orange-500/20",  icon: AlertTriangle, label: "High Priority" },
  medium:   { color: "text-yellow-400",  bg: "bg-yellow-500/10 border-yellow-500/20",  icon: AlertCircle, label: "Recommended" },
  low:      { color: "text-success",     bg: "bg-success/10 border-success/20",         icon: CheckCircle2, label: "Good Practice" },
};

export function VerdictCard({ result, onReset }: VerdictCardProps) {
  const isHighRisk = result.trustScore < 50;
  const [showExtracted, setShowExtracted] = useState(false);
  const isImage = result.inputType === "image";
  const hasEntities = isImage && result.entities && (
    (result.entities.phones?.length ?? 0) > 0 ||
    (result.entities.emails?.length ?? 0) > 0 ||
    (result.entities.urls?.length ?? 0) > 0 ||
    (result.entities.money?.length ?? 0) > 0
  );
  const hasNextSteps = (result.nextSteps?.length ?? 0) > 0;

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95, y: 20 }}
      animate={{ opacity: 1, scale: 1, y: 0 }}
      className="w-full max-w-4xl mx-auto glass-panel rounded-3xl overflow-hidden shadow-2xl"
    >
      {/* High Risk Banner */}
      <AnimatePresence>
        {isHighRisk && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            className="bg-destructive/20 border-b border-destructive/30 p-4 md:p-6 text-center"
          >
            <div className="flex items-center justify-center gap-3 text-destructive font-bold text-xl md:text-2xl tracking-tight">
              <AlertTriangle className="w-8 h-8" />
              HIGH SCAM PROBABILITY
            </div>
            <p className="mt-2 text-destructive-foreground/80 font-medium">
              Do NOT share personal information, bank details, or send any money.
            </p>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="p-8 md:p-12 space-y-12">

        {/* Top Section: Gauge & Summary */}
        <div className="flex flex-col md:flex-row items-center justify-between gap-12">
          <div className="flex-1 text-center md:text-left space-y-6">
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-secondary text-secondary-foreground font-semibold text-sm tracking-wide">
              <ShieldCheck className="w-4 h-4 text-primary" />
              Analysis Complete
            </div>

            <h2 className="text-3xl md:text-4xl font-display font-bold leading-tight">
              {result.summary.replace("⚠️ HIGH RISK — ", "").replace("HIGH RISK — ", "")}
            </h2>

            <div className="flex flex-wrap gap-4 items-center justify-center md:justify-start">
              <div className={cn(
                "px-5 py-2.5 rounded-2xl font-bold text-xl border-2 flex items-center gap-2",
                getGradeColorClass(result.grade)
              )}>
                Safety Grade: {result.grade}
              </div>
            </div>
          </div>

          <div className="flex-shrink-0 bg-background/50 p-8 rounded-full border border-white/5 shadow-inner">
            <Gauge value={result.trustScore} />
          </div>
        </div>

        {/* Entities Detected (Image only) */}
        {hasEntities && (
          <div>
            <h3 className="text-xl font-display font-bold mb-5 flex items-center gap-2">
              <Info className="w-6 h-6 text-primary" />
              Content Detected in Image
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {(result.entities!.phones?.length ?? 0) > 0 && (
                <div className="flex items-start gap-3 p-4 rounded-2xl bg-secondary/40 border border-white/10">
                  <Phone className="w-5 h-5 mt-0.5 text-primary flex-shrink-0" />
                  <div>
                    <p className="font-semibold text-sm mb-1">Phone Numbers</p>
                    {result.entities!.phones!.slice(0, 3).map((p, i) => (
                      <p key={i} className="text-sm text-muted-foreground font-mono">{p}</p>
                    ))}
                  </div>
                </div>
              )}
              {(result.entities!.emails?.length ?? 0) > 0 && (
                <div className="flex items-start gap-3 p-4 rounded-2xl bg-secondary/40 border border-white/10">
                  <Mail className="w-5 h-5 mt-0.5 text-primary flex-shrink-0" />
                  <div>
                    <p className="font-semibold text-sm mb-1">Email Addresses</p>
                    {result.entities!.emails!.slice(0, 3).map((e, i) => (
                      <p key={i} className="text-sm text-muted-foreground font-mono break-all">{e}</p>
                    ))}
                  </div>
                </div>
              )}
              {(result.entities!.urls?.length ?? 0) > 0 && (
                <div className="flex items-start gap-3 p-4 rounded-2xl bg-secondary/40 border border-white/10">
                  <Link2 className="w-5 h-5 mt-0.5 text-primary flex-shrink-0" />
                  <div>
                    <p className="font-semibold text-sm mb-1">Links Found</p>
                    {result.entities!.urls!.slice(0, 2).map((u, i) => (
                      <p key={i} className="text-sm text-muted-foreground font-mono break-all">{u}</p>
                    ))}
                  </div>
                </div>
              )}
              {(result.entities!.money?.length ?? 0) > 0 && (
                <div className="flex items-start gap-3 p-4 rounded-2xl bg-destructive/10 border border-destructive/30">
                  <DollarSign className="w-5 h-5 mt-0.5 text-destructive flex-shrink-0" />
                  <div>
                    <p className="font-semibold text-sm mb-1 text-destructive">Payment / Fee Amounts</p>
                    {result.entities!.money!.slice(0, 3).map((m, i) => (
                      <p key={i} className="text-sm text-destructive/80 font-mono">{m}</p>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Extracted Text (Image only) */}
        {result.extractedText && (
          <div className="border border-white/10 rounded-2xl overflow-hidden bg-black/20">
            <button
              onClick={() => setShowExtracted(!showExtracted)}
              className="w-full flex items-center justify-between p-5 font-semibold hover:bg-white/5 transition-colors"
            >
              <div className="flex items-center gap-2">
                <Info className="w-5 h-5 text-primary" />
                View Text Extracted from Image
              </div>
              {showExtracted ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
            </button>
            <AnimatePresence>
              {showExtracted && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: "auto", opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  className="px-5 pb-5 pt-0 text-sm font-mono text-muted-foreground whitespace-pre-wrap"
                >
                  {result.extractedText}
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        )}

        {/* Detailed Findings */}
        <div>
          <h3 className="text-xl font-display font-bold mb-6 flex items-center gap-2">
            <ShieldCheck className="w-6 h-6 text-primary" />
            Detailed Findings
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {result.flags.map((flag, i) => (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.07 }}
                key={i}
                className={cn(
                  "p-5 rounded-2xl border transition-all hover:bg-white/5",
                  flag.severity === "high"   ? "bg-destructive/5 border-destructive/20" :
                  flag.severity === "medium" ? "bg-warning/5 border-warning/20" :
                  "bg-success/5 border-success/20"
                )}
              >
                <div className="flex gap-4">
                  <div className="flex-shrink-0 mt-1">
                    {flag.severity === "high" ? (
                      <XCircle className="w-6 h-6 text-destructive" />
                    ) : flag.severity === "medium" ? (
                      <AlertTriangle className="w-6 h-6 text-warning" />
                    ) : (
                      <CheckCircle2 className="w-6 h-6 text-success" />
                    )}
                  </div>
                  <div>
                    <h4 className={cn(
                      "font-bold mb-1",
                      flag.severity === "high"   ? "text-destructive" :
                      flag.severity === "medium" ? "text-warning" :
                      "text-success"
                    )}>
                      {flag.category}
                    </h4>
                    <p className="text-sm text-muted-foreground leading-relaxed">
                      {flag.message}
                    </p>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </div>

        {/* Next Steps */}
        {hasNextSteps && (
          <div>
            <h3 className="text-xl font-display font-bold mb-6 flex items-center gap-2">
              <Zap className="w-6 h-6 text-primary" />
              What To Do Next
            </h3>
            <div className="space-y-3">
              {result.nextSteps!.map((step, i) => {
                const cfg = priorityConfig[step.priority];
                const Icon = cfg.icon;
                return (
                  <motion.div
                    key={i}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.08 }}
                    className={cn("flex gap-4 p-5 rounded-2xl border", cfg.bg)}
                  >
                    <div className="flex-shrink-0 mt-0.5">
                      <Icon className={cn("w-5 h-5", cfg.color)} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <span className={cn("text-xs font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border", cfg.bg, cfg.color)}>
                          {cfg.label}
                        </span>
                        <p className="font-semibold text-sm">{step.action}</p>
                      </div>
                      <p className="text-sm text-muted-foreground leading-relaxed flex items-start gap-1">
                        <ArrowRight className="w-3.5 h-3.5 mt-0.5 flex-shrink-0 text-muted-foreground/50" />
                        {step.detail}
                      </p>
                    </div>
                  </motion.div>
                );
              })}
            </div>
          </div>
        )}

        {/* Actions */}
        <div className="pt-6 border-t border-white/10 flex justify-center">
          <button
            onClick={onReset}
            className="flex items-center gap-2 px-8 py-4 bg-secondary hover:bg-secondary/80 text-foreground rounded-2xl font-bold transition-all active:scale-95"
          >
            <RefreshCw className="w-5 h-5" />
            Analyze Another Opportunity
          </button>
        </div>
      </div>
    </motion.div>
  );
}
