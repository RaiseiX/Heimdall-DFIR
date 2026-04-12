
export default function HeimdallLogo({ size = 32, id = 'hd', className = '', style = {} }) {
  const clipId = `${id}-eye-clip`;
  return (
    <svg
      viewBox="0 0 40 40"
      width={size}
      height={size}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      style={style}
      aria-label="Heimdall DFIR"
    >
      
      <path
        d="M 4 20 Q 20 7 36 20 Q 20 33 4 20 Z"
        stroke="currentColor"
        strokeWidth="2.2"
        strokeLinejoin="round"
      />

      <circle cx="20" cy="20" r="7.5" stroke="currentColor" strokeWidth="1.8" />

      <circle cx="20" cy="20" r="3.8" stroke="currentColor" strokeWidth="1.2" />

      <circle cx="20" cy="20" r="1.6" fill="currentColor" />

      <line x1="20" y1="11.5" x2="20" y2="13.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
      <line x1="20" y1="26.5" x2="20" y2="28.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />

      <circle cx="4.5" cy="20" r="1.6" fill="currentColor" />
      <circle cx="35.5" cy="20" r="1.6" fill="currentColor" />
    </svg>
  );
}
