import { forwardRef } from 'react';

const Textarea = forwardRef(function Textarea({ className, ...rest }, ref) {
  return <textarea className={['fl-textarea', className].filter(Boolean).join(' ')} {...rest} ref={ref} />;
});

export default Textarea;
