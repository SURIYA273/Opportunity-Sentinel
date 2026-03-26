import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function getScoreColor(score: number): string {
  if (score >= 70) return "text-success bg-success/10 border-success/20";
  if (score >= 40) return "text-warning bg-warning/10 border-warning/20";
  return "text-destructive bg-destructive/10 border-destructive/20";
}

export function getScoreColorHex(score: number): string {
  if (score >= 70) return "#22c55e"; // success
  if (score >= 40) return "#f97316"; // warning
  return "#ef4444"; // destructive
}
