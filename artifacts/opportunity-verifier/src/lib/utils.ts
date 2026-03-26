import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function getScoreColorHex(score: number): string {
  if (score >= 80) return "#10b981"; // emerald-500
  if (score >= 60) return "#84cc16"; // emerald-400
  if (score >= 40) return "#eab308"; // yellow-500
  if (score >= 20) return "#f97316"; // orange-500
  return "#ef4444"; // red-500
}

export function getGradeColorClass(grade: string): string {
  switch (grade) {
    case "A+":
    case "A":
      return "text-emerald-500 bg-emerald-500/10 border-emerald-500/20";
    case "B":
      return "text-lime-500 bg-lime-500/10 border-lime-500/20";
    case "C":
      return "text-yellow-500 bg-yellow-500/10 border-yellow-500/20";
    case "D":
      return "text-orange-500 bg-orange-500/10 border-orange-500/20";
    case "F":
      return "text-red-500 bg-red-500/10 border-red-500/20";
    default:
      return "text-muted-foreground bg-muted border-border";
  }
}
