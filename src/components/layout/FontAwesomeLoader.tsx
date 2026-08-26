"use client";

import { useEffect } from "react";

const FA_HREF = "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css";

/**
 * Next.js/React's built-in <link> handling (Float/Resource API) strips
 * attribute-based tricks like `onload="this.rel='stylesheet'"` yang biasa
 * dipakai buat non-blocking CSS loading di HTML biasa — makanya ikonnya
 * sempat nggak muncul (preload jalan, tapi nggak pernah "di-swap" jadi
 * stylesheet aktif).
 *
 * Jadi di sini di-handle manual lewat DOM API biar pasti kepasang, tanpa
 * bikin CSS ini blocking initial render.
 */
export default function FontAwesomeLoader() {
  useEffect(() => {
    if (document.querySelector(`link[href="${FA_HREF}"]`)) return;

    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = FA_HREF;
    document.head.appendChild(link);
  }, []);

  return null;
}
