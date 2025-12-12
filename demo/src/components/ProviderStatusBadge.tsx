import React from 'react';

interface ProviderStatusBadgeProps {
  isReal: boolean;
  className?: string;
}

export const ProviderStatusBadge: React.FC<ProviderStatusBadgeProps> = ({ 
  isReal, 
  className = '' 
}) => {
  return (
    <span className={`provider-badge ${isReal ? 'provider-badge-real' : 'provider-badge-mock'} ${className}`}>
      {isReal ? 'REAL' : 'MOCK'}
    </span>
  );
};