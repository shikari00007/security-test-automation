import React from 'react';
import DOMPurify from 'dompurify';

export function Comment({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
}
