import { Link } from "wouter";
import { ShieldCheck, ArrowLeft } from "lucide-react";

export default function NotFound() {
  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-background p-4">
      <div className="max-w-md w-full glass-panel rounded-3xl p-12 text-center space-y-6 border border-white/10">
        <div className="flex justify-center mb-4">
          <ShieldCheck className="w-20 h-20 text-muted-foreground opacity-50" />
        </div>
        
        <h1 className="text-5xl font-display font-extrabold tracking-tight">404</h1>
        
        <h2 className="text-xl font-semibold text-foreground/80">
          Page Not Found
        </h2>
        
        <p className="text-muted-foreground">
          The page you are looking for doesn't exist or has been moved.
        </p>

        <div className="pt-6">
          <Link href="/" className="inline-flex items-center gap-2 px-8 py-4 bg-primary text-primary-foreground font-bold rounded-xl hover:bg-primary/90 transition-all hover:scale-105 active:scale-95 shadow-lg shadow-primary/20">
            <ArrowLeft className="w-5 h-5" />
            Back to Scanner
          </Link>
        </div>
      </div>
    </div>
  );
}
