/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Premium dark theme
        'navy': {
          900: '#080B16',
          800: '#0E1324',
          700: '#131A2E',
          600: '#1a2847',
        },
        'slate': {
          400: '#929CB5',
          300: '#E8ECF7',
          200: '#b8c5e0',
        },
        'accent': {
          blue: '#528BFF',
          purple: '#9875FF',
          cyan: '#00D9FF',
          pink: '#FF006E',
        },
        'severity': {
          critical: '#FF4757',
          high: '#FFA502',
          medium: '#528BFF',
          low: '#2ED573',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Menlo', 'monospace'],
      },
      backgroundImage: {
        'gradient-nav': 'linear-gradient(180deg, rgba(82, 139, 255, 0.05) 0%, rgba(152, 117, 255, 0.02) 100%)',
        'gradient-glow': 'linear-gradient(135deg, rgba(82, 139, 255, 0.1) 0%, rgba(152, 117, 255, 0.1) 100%)',
      },
      boxShadow: {
        'glow-sm': '0 0 12px rgba(82, 139, 255, 0.15), inset 0 0 12px rgba(82, 139, 255, 0.05)',
        'glow-md': '0 0 24px rgba(82, 139, 255, 0.25), inset 0 0 24px rgba(82, 139, 255, 0.08)',
        'glow-lg': '0 0 48px rgba(82, 139, 255, 0.35), inset 0 0 48px rgba(82, 139, 255, 0.1)',
        'glass': '0 8px 32px rgba(31, 41, 55, 0.3)',
        'neon-blue': '0 0 20px rgba(82, 139, 255, 0.5), 0 0 40px rgba(82, 139, 255, 0.25)',
        'neon-purple': '0 0 20px rgba(152, 117, 255, 0.5), 0 0 40px rgba(152, 117, 255, 0.25)',
      },
      backdropBlur: {
        'xs': '4px',
        'sm': '8px',
        'md': '12px',
        'lg': '16px',
        'xl': '24px',
        '2xl': '40px',
      },
      animation: {
        'glow-pulse': 'glow-pulse 3s ease-in-out infinite',
        'float': 'float-up 4s ease-in-out infinite',
        'shimmer': 'shimmer 3s infinite',
        'slide-left': 'slide-in-left 0.6s ease-out',
        'slide-right': 'slide-in-right 0.6s ease-out',
        'scale': 'scale-in 0.5s ease-out',
      },
      scale: {
        '102': '1.02',
        '103': '1.03',
        '105': '1.05',
      },
    },
  },
  plugins: [],
}
