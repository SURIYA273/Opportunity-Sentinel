import { useState, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ShieldCheck, Link as LinkIcon, Mail, Image as ImageIcon, UploadCloud, AlertCircle } from "lucide-react";
import { useAnalyzeUrl, useAnalyzeText, useAnalyzeImage } from "@workspace/api-client-react";
import { StepLoader } from "@/components/StepLoader";
import { VerdictCard, type UnifiedResult } from "@/components/VerdictCard";
import { cn } from "@/lib/utils";

const URL_STEPS = [
  "Fetching URL metadata...",
  "Checking SSL Certificate...",
  "Reading WHOIS Records...",
  "Analyzing Page Content...",
  "Checking Contextual Keywords...",
  "Calculating Trust Score..."
];

const TEXT_STEPS = [
  "Reading text content...",
  "Checking sender domains...",
  "Scanning for hard scam keywords...",
  "Analyzing urgency & tone...",
  "Calculating Trust Score..."
];

const IMAGE_STEPS = [
  "Uploading image to server...",
  "Running OCR text extraction...",
  "Scanning extracted text...",
  "Checking for scam patterns...",
  "Calculating Trust Score..."
];

export default function Home() {
  const [activeTab, setActiveTab] = useState<"url" | "text" | "image">("url");
  const [result, setResult] = useState<UnifiedResult | null>(null);
  const [isSimulating, setIsSimulating] = useState(false);
  const [pendingResult, setPendingResult] = useState<UnifiedResult | null>(null);

  // URL State
  const [url, setUrl] = useState("");
  
  // Text State
  const [text, setText] = useState("");
  const [textType, setTextType] = useState<"text" | "email">("text");

  // Image State
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [imageBase64, setImageBase64] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Mutations
  const analyzeUrlMut = useAnalyzeUrl();
  const analyzeTextMut = useAnalyzeText();
  const analyzeImageMut = useAnalyzeImage();

  const handleUrlSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!url) return;
    setIsSimulating(true);
    analyzeUrlMut.mutate({ data: { url } }, {
      onSuccess: (data) => setPendingResult(data as UnifiedResult),
      onError: () => setIsSimulating(false) // Handle gracefully in real app
    });
  };

  const handleTextSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!text) return;
    setIsSimulating(true);
    analyzeTextMut.mutate({ data: { text, inputType: textType } }, {
      onSuccess: (data) => setPendingResult(data as UnifiedResult),
      onError: () => setIsSimulating(false)
    });
  };

  const handleImageSubmit = () => {
    if (!imageBase64) return;
    setIsSimulating(true);
    analyzeImageMut.mutate({ data: { imageBase64 } }, {
      onSuccess: (data) => setPendingResult(data as UnifiedResult),
      onError: () => setIsSimulating(false)
    });
  };

  const onSimulationComplete = () => {
    setIsSimulating(false);
    if (pendingResult) {
      setResult(pendingResult);
      setPendingResult(null);
    }
  };

  const handleReset = () => {
    setResult(null);
    setPendingResult(null);
    setUrl("");
    setText("");
    setImagePreview(null);
    setImageBase64(null);
  };

  const handleImageUpload = (file: File) => {
    if (!file.type.startsWith("image/")) return;
    
    // Preview
    const previewUrl = URL.createObjectURL(file);
    setImagePreview(previewUrl);

    // Base64 for API
    const reader = new FileReader();
    reader.onloadend = () => {
      setImageBase64(reader.result as string);
    };
    reader.readAsDataURL(file);
  };

  const getSteps = () => {
    if (activeTab === "url") return URL_STEPS;
    if (activeTab === "text") return TEXT_STEPS;
    return IMAGE_STEPS;
  };

  return (
    <div 
      className="min-h-screen w-full relative overflow-x-hidden pt-10 pb-24 px-4 sm:px-6"
      style={{
        backgroundImage: `url('${import.meta.env.BASE_URL}images/cyber-bg.png')`,
        backgroundSize: 'cover',
        backgroundPosition: 'center',
        backgroundAttachment: 'fixed',
      }}
    >
      <div className="absolute inset-0 bg-background/80 backdrop-blur-[2px]" />

      <div className="relative z-10 max-w-7xl mx-auto">
        {/* Header */}
        <header className="flex items-center justify-center mb-16 md:mb-24">
          <div className="flex items-center gap-3 bg-card/40 backdrop-blur-md px-6 py-3 rounded-full border border-white/10 shadow-lg">
            <ShieldCheck className="w-8 h-8 text-primary" />
            <h1 className="text-2xl font-display font-bold tracking-wider">
              Opp<span className="text-primary">Verifier</span>
            </h1>
          </div>
        </header>

        {/* Main Content Area */}
        <AnimatePresence mode="wait">
          {result ? (
            <motion.div key="results" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <VerdictCard result={result} onReset={handleReset} />
            </motion.div>
          ) : isSimulating ? (
            <motion.div key="loading" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <StepLoader isActive={true} steps={getSteps()} onComplete={onSimulationComplete} />
            </motion.div>
          ) : (
            <motion.div key="input" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }}>
              
              <div className="text-center mb-12">
                <h2 className="text-4xl md:text-6xl font-display font-extrabold mb-6 tracking-tight text-glow">
                  Don't get scammed on your <br className="hidden md:block"/>
                  <span className="gradient-text">next opportunity.</span>
                </h2>
                <p className="text-lg md:text-xl text-muted-foreground max-w-2xl mx-auto">
                  Verify scholarships, internships, and courses instantly using our advanced multi-layered AI scam detection engine.
                </p>
              </div>

              {/* Tabs Container */}
              <div className="max-w-3xl mx-auto glass-panel rounded-3xl p-2 md:p-4 mb-20 shadow-2xl">
                
                {/* Tab Triggers */}
                <div className="flex gap-2 mb-6 bg-black/20 p-2 rounded-2xl overflow-x-auto snap-x hide-scrollbar">
                  {[
                    { id: "url", icon: LinkIcon, label: "Verify URL" },
                    { id: "text", icon: Mail, label: "Verify Email/Text" },
                    { id: "image", icon: ImageIcon, label: "Verify Image" }
                  ].map((t) => (
                    <button
                      key={t.id}
                      onClick={() => setActiveTab(t.id as any)}
                      className={cn(
                        "flex-1 min-w-[140px] flex items-center justify-center gap-2 py-4 px-6 rounded-xl font-bold transition-all whitespace-nowrap",
                        activeTab === t.id 
                          ? "bg-primary text-primary-foreground shadow-[0_0_20px_rgba(59,130,246,0.3)]" 
                          : "hover:bg-white/5 text-muted-foreground hover:text-foreground"
                      )}
                    >
                      <t.icon className="w-5 h-5" />
                      {t.label}
                    </button>
                  ))}
                </div>

                {/* Tab Content: URL */}
                {activeTab === "url" && (
                  <form onSubmit={handleUrlSubmit} className="p-4 md:p-8 space-y-6">
                    <div>
                      <label className="block text-sm font-semibold text-muted-foreground mb-3 uppercase tracking-wider ml-2">
                        Paste Opportunity Link
                      </label>
                      <input
                        type="url"
                        placeholder="https://example.com/apply-now..."
                        value={url}
                        onChange={(e) => setUrl(e.target.value)}
                        required
                        className="w-full bg-black/40 border-2 border-white/10 rounded-2xl px-6 py-5 text-lg text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary focus:ring-4 focus:ring-primary/20 transition-all"
                      />
                    </div>
                    <button
                      type="submit"
                      disabled={!url}
                      className="w-full bg-primary hover:bg-primary/90 disabled:opacity-50 disabled:hover:bg-primary text-primary-foreground text-xl font-bold py-5 rounded-2xl shadow-lg shadow-primary/25 transition-all hover:shadow-xl hover:-translate-y-1 active:translate-y-0"
                    >
                      Analyze URL
                    </button>
                  </form>
                )}

                {/* Tab Content: TEXT */}
                {activeTab === "text" && (
                  <form onSubmit={handleTextSubmit} className="p-4 md:p-8 space-y-6">
                    <div>
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-3 ml-2 gap-3">
                        <label className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">
                          Paste Content
                        </label>
                        <div className="flex bg-black/30 rounded-lg p-1">
                          <button
                            type="button"
                            onClick={() => setTextType("text")}
                            className={cn("px-4 py-1.5 rounded-md text-sm font-medium transition-colors", textType === "text" ? "bg-white/10 text-foreground" : "text-muted-foreground")}
                          >
                            Social Post
                          </button>
                          <button
                            type="button"
                            onClick={() => setTextType("email")}
                            className={cn("px-4 py-1.5 rounded-md text-sm font-medium transition-colors", textType === "email" ? "bg-white/10 text-foreground" : "text-muted-foreground")}
                          >
                            Email
                          </button>
                        </div>
                      </div>
                      <textarea
                        placeholder={`Paste the ${textType === "email" ? "email body including sender info" : "WhatsApp message, Telegram forward, or job post"} here...`}
                        value={text}
                        onChange={(e) => setText(e.target.value)}
                        required
                        rows={6}
                        className="w-full bg-black/40 border-2 border-white/10 rounded-2xl px-6 py-5 text-lg text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary focus:ring-4 focus:ring-primary/20 transition-all resize-y min-h-[150px]"
                      />
                    </div>
                    <button
                      type="submit"
                      disabled={!text}
                      className="w-full bg-primary hover:bg-primary/90 disabled:opacity-50 disabled:hover:bg-primary text-primary-foreground text-xl font-bold py-5 rounded-2xl shadow-lg shadow-primary/25 transition-all hover:shadow-xl hover:-translate-y-1 active:translate-y-0"
                    >
                      Analyze Text
                    </button>
                  </form>
                )}

                {/* Tab Content: IMAGE */}
                {activeTab === "image" && (
                  <div className="p-4 md:p-8 space-y-6">
                    <label className="block text-sm font-semibold text-muted-foreground mb-3 uppercase tracking-wider ml-2">
                      Upload Screenshot (Instagram Ad, Poster, etc.)
                    </label>
                    
                    {!imagePreview ? (
                      <div
                        onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
                        onDragLeave={() => setIsDragging(false)}
                        onDrop={(e) => {
                          e.preventDefault();
                          setIsDragging(false);
                          if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                            handleImageUpload(e.dataTransfer.files[0]);
                          }
                        }}
                        onClick={() => fileInputRef.current?.click()}
                        className={cn(
                          "w-full h-64 border-3 border-dashed rounded-3xl flex flex-col items-center justify-center cursor-pointer transition-all",
                          isDragging ? "border-primary bg-primary/10" : "border-white/20 bg-black/20 hover:bg-black/40 hover:border-white/40"
                        )}
                      >
                        <UploadCloud className={cn("w-16 h-16 mb-4", isDragging ? "text-primary" : "text-muted-foreground")} />
                        <p className="text-lg font-semibold text-foreground mb-2">
                          Drag & drop a screenshot here
                        </p>
                        <p className="text-sm text-muted-foreground">
                          or click to browse files (PNG, JPG)
                        </p>
                      </div>
                    ) : (
                      <div className="relative w-full h-64 rounded-3xl overflow-hidden border-2 border-white/20 bg-black/40 group">
                        <img src={imagePreview} alt="Preview" className="w-full h-full object-contain p-2" />
                        <div className="absolute inset-0 bg-black/60 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                          <button 
                            onClick={() => { setImagePreview(null); setImageBase64(null); }}
                            className="bg-destructive hover:bg-destructive/80 text-white px-6 py-3 rounded-xl font-bold"
                          >
                            Remove Image
                          </button>
                        </div>
                      </div>
                    )}
                    
                    <input 
                      type="file" 
                      accept="image/*" 
                      className="hidden" 
                      ref={fileInputRef}
                      onChange={(e) => {
                        if (e.target.files && e.target.files[0]) {
                          handleImageUpload(e.target.files[0]);
                        }
                      }}
                    />

                    <button
                      onClick={handleImageSubmit}
                      disabled={!imageBase64}
                      className="w-full bg-primary hover:bg-primary/90 disabled:opacity-50 disabled:hover:bg-primary text-primary-foreground text-xl font-bold py-5 rounded-2xl shadow-lg shadow-primary/25 transition-all hover:shadow-xl hover:-translate-y-1 active:translate-y-0"
                    >
                      Extract & Analyze Text
                    </button>
                  </div>
                )}
              </div>

              {/* Scam Encyclopedia */}
              <div className="mt-32">
                <div className="text-center mb-12">
                  <h3 className="text-3xl font-display font-bold mb-4">Scam Encyclopedia</h3>
                  <p className="text-muted-foreground">Learn the red flags of common educational scams.</p>
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                  <div className="glass-card p-6 rounded-2xl hover:-translate-y-1">
                    <div className="w-12 h-12 rounded-full bg-destructive/20 text-destructive flex items-center justify-center mb-6">
                      <AlertCircle className="w-6 h-6" />
                    </div>
                    <h4 className="text-lg font-bold mb-3">The Upfront Fee Scam</h4>
                    <p className="text-muted-foreground text-sm leading-relaxed">
                      Real internships pay you. If a company asks for a "training fee", "laptop deposit", or "registration fee", it is 100% a scam.
                    </p>
                  </div>
                  
                  <div className="glass-card p-6 rounded-2xl hover:-translate-y-1">
                    <div className="w-12 h-12 rounded-full bg-warning/20 text-warning flex items-center justify-center mb-6">
                      <Mail className="w-6 h-6" />
                    </div>
                    <h4 className="text-lg font-bold mb-3">Free Email Sender</h4>
                    <p className="text-muted-foreground text-sm leading-relaxed">
                      Legitimate multinational companies do not send official offer letters from @gmail.com or @yahoo.com addresses.
                    </p>
                  </div>
                  
                  <div className="glass-card p-6 rounded-2xl hover:-translate-y-1">
                    <div className="w-12 h-12 rounded-full bg-primary/20 text-primary flex items-center justify-center mb-6">
                      <Globe className="w-6 h-6" />
                    </div>
                    <h4 className="text-lg font-bold mb-3">New Domain Warning</h4>
                    <p className="text-muted-foreground text-sm leading-relaxed">
                      Scammers constantly spin up new websites. If an "established" company has a website registered 12 days ago, be extremely cautious.
                    </p>
                  </div>
                  
                  <div className="glass-card p-6 rounded-2xl hover:-translate-y-1">
                    <div className="w-12 h-12 rounded-full bg-purple-500/20 text-purple-400 flex items-center justify-center mb-6">
                      <ShieldCheck className="w-6 h-6" />
                    </div>
                    <h4 className="text-lg font-bold mb-3">Guaranteed Selection</h4>
                    <p className="text-muted-foreground text-sm leading-relaxed">
                      If an opportunity promises "100% placement" or hires you without any interview process, they are likely harvesting your data.
                    </p>
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
