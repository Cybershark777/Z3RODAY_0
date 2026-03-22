export default function ErrorMessage({ message }: { message: string }) {
  return (
    <div className="error-state">
      <span>⚠ {message}</span>
    </div>
  )
}
