import { Link } from "wouter";
import { ShieldAlert } from "lucide-react";

export default function NotFound() {
  return (
    <div className="min-h-screen w-full flex flex-col items-center justify-center bg-background text-foreground relative overflow-hidden">
      {/* Background Image & Overlay */}
      <div className="absolute inset-0 z-0">
        <img 
          src={`${import.meta.env.BASE_URL}images/cyber-bg.png`} 
          alt="Cyber Background" 
          className="w-full h-full object-cover opacity-20 grayscale"
        />
        <div className="absolute inset-0 bg-background/80 backdrop-blur-sm" />
      </div>

      <div className="relative z-10 text-center flex flex-col items-center">
        <ShieldAlert className="w-24 h-24 text-destructive mb-6 opacity-80" />
        <h1 className="text-6xl font-display font-bold mb-4 tracking-tight">404</h1>
        <p className="text-xl text-muted-foreground mb-8 max-w-md">
          The page you are looking for has been moved, deleted, or possibly intercepted.
        </p>
        <Link href="/" className="px-6 py-3 rounded-xl bg-primary text-primary-foreground font-semibold hover:bg-primary/90 transition-colors">
          Return to Safety
        </Link>
      </div>
    </div>
  );
}
