import type { NextConfig } from "next";

const FASTAPI = "http://localhost:8000";

const nextConfig: NextConfig = {
  cacheComponents: true,
  partialPrefetching: true,
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
  async rewrites() {
    return {
      // beforeFiles: checked BEFORE filesystem routes (app/api/ routes)
      beforeFiles: [
        {
          source: "/api/:path*",
          destination: `${FASTAPI}/api/:path*`,
        },
      ],
      afterFiles: [],
      fallback: [],
    };
  },
};

export default nextConfig;
