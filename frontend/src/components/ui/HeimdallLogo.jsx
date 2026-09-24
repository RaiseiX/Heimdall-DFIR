
export default function HeimdallLogo({ size = 32, id = 'hd', className = '', style = {} }) {
  return (
    <img
      src="/assets/heimdall-mark.png"
      width={size}
      height={size}
      alt="Heimdall DFIR"
      className={className}
      style={{ display: 'block', objectFit: 'contain', flexShrink: 0, ...style }}
    />
  );
}
