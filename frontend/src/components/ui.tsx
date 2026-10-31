import type { ButtonHTMLAttributes, ReactNode } from "react";

/* Shared UI primitives. Existing views can adopt these gradually; the
   matching .btn / .badge / .card classes in index.css work on their own too. */

export function Spinner({ className = "h-4 w-4" }: { className?: string }) {
  return (
    <svg className={`animate-spin ${className}`} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="3" opacity="0.2" />
      <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}

type ButtonVariant = "primary" | "secondary" | "ghost" | "danger";

const VARIANT_CLASS: Record<ButtonVariant, string> = {
  primary: "btn btn-primary",
  secondary: "btn",
  ghost: "btn btn-ghost",
  danger: "btn btn-danger",
};

export type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant;
  small?: boolean;
  loading?: boolean;
};

export function Button({
  variant = "secondary",
  small = false,
  loading = false,
  disabled,
  type = "button",
  className = "",
  children,
  ...rest
}: ButtonProps) {
  return (
    <button
      type={type}
      disabled={disabled || loading}
      className={`${VARIANT_CLASS[variant]} ${small ? "btn-sm" : ""} ${className}`.trim()}
      {...rest}
    >
      {loading && <Spinner className="h-3.5 w-3.5" />}
      {children}
    </button>
  );
}

export type BadgeTone = "neutral" | "accent" | "info" | "warning" | "danger";

const BADGE_CLASS: Record<BadgeTone, string> = {
  neutral: "badge",
  accent: "badge badge-accent",
  info: "badge badge-info",
  warning: "badge badge-warning",
  danger: "badge badge-danger",
};

export function Badge({ tone = "neutral", children }: { tone?: BadgeTone; children: ReactNode }) {
  return <span className={BADGE_CLASS[tone]}>{children}</span>;
}

/** Maps Metasploit's module rank labels to a badge colour. */
export function rankTone(label: string): BadgeTone {
  switch (label.toLowerCase()) {
    case "excellent":
    case "great":
      return "accent";
    case "good":
      return "info";
    case "normal":
    case "average":
      return "warning";
    case "low":
    case "manual":
      return "danger";
    default:
      return "neutral";
  }
}

export function RankBadge({ label }: { label: string }) {
  return <Badge tone={rankTone(label)}>{label}</Badge>;
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-14 text-center">
      <div className="flex h-10 w-10 items-center justify-center rounded-full border border-border-strong bg-bg-tertiary text-gray-500">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <circle cx="12" cy="12" r="9" />
          <path d="M8 12h8" />
        </svg>
      </div>
      <h3 className="text-sm font-medium text-gray-200">{title}</h3>
      {description && <p className="max-w-sm text-xs leading-5 text-gray-500">{description}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

export function Skeleton({ className = "h-4 w-full" }: { className?: string }) {
  return <div className={`skeleton ${className}`} aria-hidden="true" />;
}
