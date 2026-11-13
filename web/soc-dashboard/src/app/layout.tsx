import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'AegisKernel | Hardware-Accelerated 3D SOC Threat Platform',
  description: 'Autonomous Agentic Threat-Hunting & Kernel-Level Deception Platform',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="antialiased bg-[#06080e] text-[#e1e7f0]">
        {children}
      </body>
    </html>
  );
}
