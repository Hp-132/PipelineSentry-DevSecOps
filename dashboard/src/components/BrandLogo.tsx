interface BrandLogoProps {
  size?: number
  className?: string
}

/** PipelineSentry mark: shield + pipeline nodes */
export const BrandLogo: React.FC<BrandLogoProps> = ({ size = 36, className = '' }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 40 40"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
    className={className}
    aria-hidden
  >
    <defs>
      <linearGradient id="ps-brand-gradient" x1="8" y1="6" x2="32" y2="34" gradientUnits="userSpaceOnUse">
        <stop stopColor="#528BFF" />
        <stop offset="1" stopColor="#9875FF" />
      </linearGradient>
    </defs>
    <rect x="2" y="2" width="36" height="36" rx="10" fill="url(#ps-brand-gradient)" fillOpacity="0.15" />
    <rect x="2" y="2" width="36" height="36" rx="10" stroke="url(#ps-brand-gradient)" strokeOpacity="0.45" strokeWidth="1.25" />
    <path
      d="M20 8.5L28 12.2V19.5C28 25.2 24.5 29.8 20 31.5C15.5 29.8 12 25.2 12 19.5V12.2L20 8.5Z"
      stroke="url(#ps-brand-gradient)"
      strokeWidth="1.5"
      strokeLinejoin="round"
      fill="rgba(82, 139, 255, 0.08)"
    />
    <path
      d="M14 19.5H26M17 19.5V19.5M20 19.5V19.5M23 19.5V19.5"
      stroke="#E8ECF7"
      strokeWidth="1.75"
      strokeLinecap="round"
    />
    <circle cx="17" cy="19.5" r="2" fill="#528BFF" />
    <circle cx="20" cy="19.5" r="2" fill="#7BA3FF" />
    <circle cx="23" cy="19.5" r="2" fill="#9875FF" />
    <path d="M20 14.5V17" stroke="#E8ECF7" strokeWidth="1.5" strokeLinecap="round" />
    <circle cx="20" cy="13.25" r="1.25" fill="#00D9FF" />
  </svg>
)
