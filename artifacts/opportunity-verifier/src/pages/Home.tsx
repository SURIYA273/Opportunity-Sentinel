import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useAnalyzeUrl } from "@workspace/api-client-react";
import { type AnalyzeResult } from "@workspace/api-client-react/src/generated/api.schemas";
import { 
  ShieldAlert,
  ShieldCheck,
  Search, 
  Lock, 
  Globe, 
  FileText, 
  Database,
  ArrowRight,
  AlertTriangle,
  Info,
  CheckCircle,
  XCircle
} from "lucide-react";
import { StepLoader } from "@/components/StepLoader";
import { Gauge } from "@/components/Gauge";
import { cn, getScoreColor } from "@/lib/utils";

export default function Home() {
  const [url, setUrl] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalyzeResult | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const analyzeMutation = useAnalyzeUrl();

  const handleAnalyze = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!url || !url.trim()) return;

    // Basic URL format check
    if (!/^https?:\/\//i.test(url.trim())) {
      setErrorMsg("Please enter a valid URL starting with http:// or https://");
      return;
    }

    setErrorMsg(null);
    setIsAnalyzing(true);
    setResult(null);

    try {
      // Start the mutation
      const data = await analyzeMutation.mutateAsync({ data: { url: url.trim() } });
      
      // The StepLoader will call handleStepsComplete after ~4-5 seconds
      // We store the data, but wait for the loader to finish before revealing
      // using a sneaky hidden state, but for simplicity we'll just wait here
      // if the API returns instantly, we still want the cool animation to finish.
      // Handled by the onComplete callback of StepLoader.
      
      // Store result globally, but we only show it when isAnalyzing turns false
      // Let's store it in a temporary variable that gets set to main state later
      (window as any)._tempResult = data;

    } catch (err: any) {
      console.error(err);
      setErrorMsg(err.message || "Failed to analyze URL. The server might be unreachable.");
      setIsAnalyzing(false);
    }
  };

  const handleStepsComplete = () => {
    setIsAnalyzing(false);
    setResult((window as any)._tempResult);
    (window as any)._tempResult = null;
  };

  const reset = () => {
    setResult(null);
    setUrl("");
    setErrorMsg(null);
  };

  return (
    <div className="min-h-screen relative overflow-hidden flex flex-col">
      {/* Background Image & Overlay */}
      <div className="fixed inset-0 z-0">
        <img 
          src={`${import.meta.env.BASE_URL}images/cyber-bg.png`} 
          alt="Cyber Background" 
          className="w-full h-full object-cover opacity-30"
        />
        <div className="absolute inset-0 bg-gradient-to-b from-background/80 via-background/95 to-background" />
      </div>

      <header className="relative z-10 w-full py-6 px-6 md:px-12 flex items-center justify-between border-b border-white/5">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-primary/20 border border-primary/30 flex items-center justify-center text-primary shadow-[0_0_15px_rgba(59,130,246,0.3)]">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <span className="font-display font-bold text-xl tracking-wide hidden sm:block">
            Opp<span className="text-primary">Verifier</span>
          </span>
        </div>
      </header>

      <main className="flex-1 relative z-10 w-full max-w-5xl mx-auto px-4 py-12 md:py-24 flex flex-col items-center justify-center">
        
        <AnimatePresence mode="wait">
          
          {/* STATE 1: INPUT */}
          {!isAnalyzing && !result && (
            <motion.div 
              key="input"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, filter: "blur(10px)" }}
              transition={{ duration: 0.4 }}
              className="w-full max-w-3xl flex flex-col items-center text-center"
            >
              <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 text-primary text-sm font-medium mb-8">
                <Lock className="w-4 h-4" />
                <span>Protect yourself from educational scams</span>
              </div>
              
              <h1 className="text-4xl md:text-6xl font-display font-bold leading-tight mb-6">
                Don't get scammed on your next <span className="text-transparent bg-clip-text bg-gradient-to-r from-primary to-blue-400">opportunity.</span>
              </h1>
              
              <p className="text-lg md:text-xl text-muted-foreground mb-12 max-w-2xl">
                Paste the URL of any scholarship, internship, or online course below. Our AI-driven engine will analyze technical trust signals and content red flags instantly.
              </p>

              <form onSubmit={handleAnalyze} className="w-full relative group">
                <div className="absolute -inset-1 bg-gradient-to-r from-primary/50 to-blue-600/50 rounded-2xl blur opacity-25 group-hover:opacity-40 transition duration-500"></div>
                <div className="relative flex items-center w-full bg-card border border-white/10 rounded-2xl p-2 shadow-2xl focus-within:border-primary/50 transition-colors">
                  <div className="pl-4 pr-2 text-muted-foreground">
                    <Globe className="w-6 h-6" />
                  </div>
                  <input
                    type="text"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="https://example.com/apply-now..."
                    className="flex-1 bg-transparent border-none outline-none py-4 text-lg font-mono text-foreground placeholder:text-muted-foreground/50 placeholder:font-sans focus:ring-0"
                    disabled={isAnalyzing}
                  />
                  <button
                    type="submit"
                    disabled={!url || isAnalyzing}
                    className="px-6 md:px-8 py-4 rounded-xl font-semibold bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-all active:scale-95 flex items-center gap-2"
                  >
                    <span>Analyze</span>
                    <ArrowRight className="w-5 h-5" />
                  </button>
                </div>
              </form>

              {errorMsg && (
                <motion.div 
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="mt-6 flex items-center gap-2 text-destructive bg-destructive/10 px-4 py-3 rounded-lg border border-destructive/20"
                >
                  <AlertTriangle className="w-5 h-5" />
                  <span className="font-medium">{errorMsg}</span>
                </motion.div>
              )}

              <div className="mt-16 flex flex-wrap justify-center gap-8 text-muted-foreground/60">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-5 h-5" />
                  <span className="text-sm font-medium">SSL Verified</span>
                </div>
                <div className="flex items-center gap-2">
                  <Database className="w-5 h-5" />
                  <span className="text-sm font-medium">WHOIS Analysis</span>
                </div>
                <div className="flex items-center gap-2">
                  <FileText className="w-5 h-5" />
                  <span className="text-sm font-medium">Content Heuristics</span>
                </div>
              </div>
            </motion.div>
          )}

          {/* STATE 2: LOADING */}
          {isAnalyzing && (
            <motion.div 
              key="loading"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 1.05 }}
              transition={{ duration: 0.5 }}
              className="w-full"
            >
              <StepLoader isActive={isAnalyzing} onComplete={handleStepsComplete} />
            </motion.div>
          )}

          {/* STATE 3: RESULTS */}
          {!isAnalyzing && result && (
            <motion.div 
              key="results"
              initial={{ opacity: 0, y: 40 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, staggerChildren: 0.1 }}
              className="w-full flex flex-col gap-8"
            >
              
              {/* Top Row: Score & Summary */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                
                {/* Score Card */}
                <div className="glass-panel rounded-3xl p-8 flex flex-col items-center justify-center relative overflow-hidden lg:col-span-1">
                  <div className="absolute top-0 right-0 w-32 h-32 bg-primary/10 blur-[50px] rounded-full -mr-10 -mt-10" />
                  
                  <h2 className="text-xl font-display font-semibold mb-6 text-foreground/80 w-full text-center">Safety Analysis</h2>
                  
                  <Gauge value={result.trustScore} />
                  
                  <div className="mt-8 flex flex-col items-center gap-2">
                    <div className={cn(
                      "px-6 py-2 rounded-2xl border font-display font-bold text-3xl flex items-center gap-3",
                      getScoreColor(result.trustScore)
                    )}>
                      Grade: {result.grade}
                    </div>
                  </div>
                </div>

                {/* Summary & Scam Warning */}
                <div className="lg:col-span-2 flex flex-col gap-6">
                  
                  <div className="glass-panel rounded-3xl p-8 flex-1 flex flex-col justify-center">
                    <h3 className="text-lg text-muted-foreground font-medium mb-2">Verdict for</h3>
                    <p className="font-mono text-primary break-all mb-6 text-sm">{result.url}</p>
                    
                    <p className="text-2xl md:text-3xl font-display font-semibold leading-relaxed">
                      {result.summary}
                    </p>
                  </div>

                  {result.trustScore < 70 && (
                    <motion.div 
                      initial={{ opacity: 0, x: 20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: 0.4 }}
                      className="bg-destructive/10 border border-destructive/30 rounded-3xl p-6 flex gap-4"
                    >
                      <div className="flex-shrink-0 w-12 h-12 bg-destructive/20 rounded-full flex items-center justify-center text-destructive">
                        <AlertTriangle className="w-6 h-6" />
                      </div>
                      <div>
                        <h4 className="text-destructive font-bold text-lg mb-1">Scam Warning</h4>
                        <p className="text-destructive-foreground/90 text-sm md:text-base leading-relaxed">
                          Real internships and jobs will <strong>never</strong> ask you to pay an upfront processing fee, security deposit, or buy your own equipment from a "preferred vendor". Legitimate scholarships do not require application fees.
                        </p>
                      </div>
                    </motion.div>
                  )}
                </div>
              </div>

              {/* Bottom Row: Signals & Flags */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mt-4">
                
                {/* Trust Signals */}
                <div className="glass-panel rounded-3xl p-8">
                  <h3 className="text-xl font-display font-bold mb-6 flex items-center gap-2">
                    <ShieldCheck className="w-6 h-6 text-primary" />
                    Technical Trust Signals
                  </h3>
                  
                  <div className="space-y-4">
                    <SignalRow 
                      label="SSL Certificate" 
                      value={result.sslValid ? "Valid & Secure" : "Missing or Invalid"} 
                      good={result.sslValid} 
                    />
                    <SignalRow 
                      label="Domain Extension" 
                      value={result.domainExtension.toUpperCase()} 
                      good={['.EDU', '.GOV', '.ORG', '.COM'].includes(result.domainExtension.toUpperCase())} 
                    />
                    <SignalRow 
                      label="Domain Age" 
                      value={result.domainAgeDays ? `${result.domainAgeDays} days` : "Unknown"} 
                      good={result.domainAgeDays ? result.domainAgeDays > 180 : false} 
                      warning={result.domainAgeDays ? result.domainAgeDays <= 180 && result.domainAgeDays > 30 : true}
                    />
                    <SignalRow 
                      label="Data Collection" 
                      value={`${result.inputFieldCount} input fields found`} 
                      good={result.inputFieldCount < 5} 
                      warning={result.inputFieldCount >= 5 && result.inputFieldCount < 10}
                    />
                  </div>
                </div>

                {/* Red Flags */}
                <div className="glass-panel rounded-3xl p-8">
                  <h3 className="text-xl font-display font-bold mb-6 flex items-center gap-2">
                    <AlertTriangle className="w-6 h-6 text-warning" />
                    Detailed Findings
                  </h3>
                  
                  {result.flags.length === 0 ? (
                    <div className="h-full min-h-[200px] flex flex-col items-center justify-center text-muted-foreground border border-dashed border-white/10 rounded-2xl bg-black/20">
                      <CheckCircle className="w-10 h-10 text-success/50 mb-3" />
                      <p>No significant red flags detected.</p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {result.flags.map((flag, idx) => (
                        <div 
                          key={idx} 
                          className={cn(
                            "p-4 rounded-xl border flex gap-4 items-start",
                            flag.severity === 'high' ? "bg-destructive/5 border-destructive/20 text-destructive-foreground" :
                            flag.severity === 'medium' ? "bg-warning/5 border-warning/20 text-warning-foreground" :
                            "bg-white/5 border-white/10 text-foreground"
                          )}
                        >
                          <div className="mt-0.5">
                            {flag.severity === 'high' ? <XCircle className="w-5 h-5 text-destructive" /> :
                             flag.severity === 'medium' ? <AlertTriangle className="w-5 h-5 text-warning" /> :
                             <Info className="w-5 h-5 text-primary" />}
                          </div>
                          <div>
                            <div className="flex items-center gap-2 mb-1">
                              <span className="text-xs font-bold uppercase tracking-wider opacity-70">{flag.category}</span>
                              <span className={cn(
                                "text-[10px] px-2 py-0.5 rounded-full font-semibold",
                                flag.severity === 'high' ? "bg-destructive/20 text-destructive" :
                                flag.severity === 'medium' ? "bg-warning/20 text-warning" :
                                "bg-primary/20 text-primary"
                              )}>
                                {flag.severity} risk
                              </span>
                            </div>
                            <p className="text-sm opacity-90">{flag.message}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

              </div>

              <div className="flex justify-center mt-8">
                <button
                  onClick={reset}
                  className="px-8 py-4 rounded-xl font-semibold bg-white/5 hover:bg-white/10 border border-white/10 text-foreground transition-all active:scale-95 flex items-center gap-2"
                >
                  <Search className="w-5 h-5" />
                  Analyze Another URL
                </button>
              </div>

            </motion.div>
          )}
        </AnimatePresence>
      </main>
    </div>
  );
}

function SignalRow({ label, value, good, warning }: { label: string, value: string, good: boolean, warning?: boolean }) {
  return (
    <div className="flex items-center justify-between p-4 rounded-xl bg-black/20 border border-white/5">
      <span className="text-muted-foreground font-medium">{label}</span>
      <div className="flex items-center gap-2">
        <span className="font-semibold text-foreground">{value}</span>
        {good ? (
          <CheckCircle className="w-5 h-5 text-success" />
        ) : warning ? (
          <AlertTriangle className="w-5 h-5 text-warning" />
        ) : (
          <XCircle className="w-5 h-5 text-destructive" />
        )}
      </div>
    </div>
  );
}
