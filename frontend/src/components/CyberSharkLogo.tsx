export default function CyberSharkLogo({ height = 52 }: { height?: number }) {
  return (
    <img
      src="/logo.png"
      alt="CyberShark Security"
      height={height}
      width={height} // square source image
      style={{ display: 'block', flexShrink: 0, objectFit: 'contain' }}
    />
  )
}
