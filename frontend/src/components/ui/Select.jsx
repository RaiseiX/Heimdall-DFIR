import { forwardRef } from 'react';

const Select = forwardRef(function Select({ className, ...rest }, ref) {
  return <select className={['fl-select', className].filter(Boolean).join(' ')} {...rest} ref={ref} />;
});

export default Select;
