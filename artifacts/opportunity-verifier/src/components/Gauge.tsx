import { motion } from "framer-motion";
import { getScoreColorHex } from "@/lib/utils";

interface GaugeProps {
  value: number;
  max?: number;
  size?: number;
  strokeWidth?: number;
}

export function Gauge({ value, max = 100, size = 240, strokeWidth = 16 }: GaugeProps) {
  const radius = (size - strokeWidth) / 2;
  const circumference = radius * Math.PI; // Semi-circle
  
  // Calculate percentage (0 to 1)
  const percentage = Math.min(Math.max(value / max, 0), 1);
  const strokeDashoffset = circumference - percentage * circumference;
  
  const color = getScoreColorHex(value);

  return (
    <div className="relative flex flex-col items-center justify-end" style={{ width: size, height: size / 2 + 20 }}>
      <svg
        width={size}
        height={size / 2}
        viewBox={`0 0 ${size} ${size / 2}`}
        className="overflow-visible"
      >
        {/* Background Arc */}
        <path
          d={`M ${strokeWidth / 2} ${size / 2} A ${radius} ${radius} 0 0 1 ${size - strokeWidth / 2} ${size / 2}`}
          fill="none"
          stroke="hsl(var(--secondary))"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
        />
        
        {/* Value Arc */}
        <motion.path
          d={`M ${strokeWidth / 2} ${size / 2} A ${radius} ${radius} 0 0 1 ${size - strokeWidth / 2} ${size / 2}`}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset }}
          transition={{ duration: 1.5, ease: "easeOut", delay: 0.2 }}
          style={{
            filter: `drop-shadow(0px 0px 12px ${color}60)`,
          }}
        />
      </svg>
      
      <div className="absolute bottom-0 left-1/2 -translate-x-1/2 text-center translate-y-6">
        <motion.span 
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 1 }}
          className="text-6xl font-display font-extrabold"
          style={{ color, textShadow: `0 0 20px ${color}50` }}
        >
          {Math.round(value)}
        </motion.span>
        <div className="text-sm text-muted-foreground uppercase tracking-wider font-semibold mt-1">
          Trust Score
        </div>
      </div>
    </div>
  );
}
