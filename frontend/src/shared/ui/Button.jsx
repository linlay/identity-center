export function Button({
  children,
  variant = 'primary',
  loading = false,
  className = '',
  type = 'button',
  ...props
}) {
  const classes = ['btn', `btn-${variant}`, loading ? 'is-loading' : '', className].filter(Boolean).join(' ');

  return (
    <button type={type} className={classes} disabled={loading || props.disabled} {...props}>
      {loading ? 'Processing...' : children}
    </button>
  );
}
