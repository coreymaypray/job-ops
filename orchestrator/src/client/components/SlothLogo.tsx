import type React from "react";

interface SlothLogoProps {
  className?: string;
}

export const SlothLogo: React.FC<SlothLogoProps> = ({ className = "size-8" }) => (
  <svg
    viewBox="0 0 64 64"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
    className={className}
  >
    {/* Face shape */}
    <circle cx="32" cy="34" r="24" fill="#00D4AA" opacity="0.15" />
    <circle cx="32" cy="34" r="24" stroke="#00D4AA" strokeWidth="2.5" />

    {/* Eye patches (characteristic sloth markings) */}
    <ellipse cx="22" cy="30" rx="8" ry="9" fill="#7B61FF" opacity="0.25" />
    <ellipse cx="42" cy="30" rx="8" ry="9" fill="#7B61FF" opacity="0.25" />

    {/* Eyes */}
    <circle cx="22" cy="31" r="3.5" fill="#00D4AA" />
    <circle cx="42" cy="31" r="3.5" fill="#00D4AA" />
    <circle cx="23" cy="30" r="1.5" fill="white" />
    <circle cx="43" cy="30" r="1.5" fill="white" />

    {/* Nose */}
    <ellipse cx="32" cy="39" rx="3" ry="2.5" fill="#7B61FF" opacity="0.6" />

    {/* Smile */}
    <path
      d="M27 43 Q32 47 37 43"
      stroke="#00D4AA"
      strokeWidth="2"
      strokeLinecap="round"
      fill="none"
    />

    {/* Ears */}
    <circle cx="12" cy="20" r="5" fill="#00D4AA" opacity="0.3" />
    <circle cx="52" cy="20" r="5" fill="#00D4AA" opacity="0.3" />
  </svg>
);
