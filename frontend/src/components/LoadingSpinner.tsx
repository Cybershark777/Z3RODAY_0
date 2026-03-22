export default function LoadingSpinner({ message = 'Loading...' }: { message?: string }) {
  return (
    <div className="loading-state">
      <div className="spinner" />
      <span>{message}</span>
    </div>
  )
}
