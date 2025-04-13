import HtmlWebpackPlugin from 'html-webpack-plugin'; // Use import
import path from 'path';
import { fileURLToPath } from 'url'; // Needed for __dirname in ESM

// Recreate __dirname for ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Use export default for the configuration function
export default (env, argv) => {
  // Determine mode (production or development)
  const isProduction = argv.mode === 'production';

  return {
    // Entry point for the application bundle
    entry: './src/index.tsx', // Relative path to the main TSX file

    // Output configuration for the bundled file
    output: {
      // Use content hash in filename for production builds for cache busting
      filename: isProduction ? 'bundle.[contenthash].js' : 'bundle.js',
      // Output directory (absolute path)
      path: path.resolve(__dirname, 'dist'),
      // Base path for all assets within the application
      publicPath: '/',
      // Clean the output directory before each build
      clean: true,
    },

    // Target environment for the bundle
    target: 'web', // Bundle for web browsers

    // Mode for webpack (influences optimizations and environment variables)
    mode: isProduction ? 'production' : 'development',

    // Module resolution and loaders configuration
    module: {
      rules: [
        {
          // Process JavaScript and TypeScript files using Babel
          test: /\.(ts|tsx|js|jsx)$/,
          exclude: /node_modules/, // Don't process files in node_modules
          use: {
            loader: 'babel-loader', // Use Babel to transpile
            options: {
              // Babel presets for modern JavaScript, React, and TypeScript
              presets: [
                '@babel/preset-env',
                // Use automatic runtime for React 17+ JSX transform
                ['@babel/preset-react', { runtime: 'automatic' }],
                '@babel/preset-typescript',
              ],
            },
          },
        },
        {
          // Process CSS files
          test: /\.css$/i,
          use: [
            'style-loader', // Injects styles into the DOM via <style> tags
            'css-loader', // Resolves CSS @import and url() paths
            'postcss-loader', // Processes CSS with PostCSS (for Tailwind CSS and autoprefixing)
          ],
        },
      ],
    },

    // File extensions to resolve automatically
    resolve: {
      extensions: ['.tsx', '.ts', '.js', '.jsx'], // Order matters
      alias: {
        // Define aliases for cleaner imports (matches tsconfig.json)
        '@': path.resolve(__dirname, 'src'),
      },
    },

    // Source map generation strategy
    devtool: isProduction ? 'source-map' : 'inline-source-map', // More detailed maps for dev

    // Configuration for webpack-dev-server
    devServer: {
      // Serve static files from the 'public' directory (if you have one)
      static: {
        directory: path.join(__dirname, 'public'), // Optional: if you have static assets outside 'src'
      },
      compress: true, // Enable gzip compression for served files
      port: 3000, // Port for the development server
      hot: true, // Enable Hot Module Replacement (HMR) for faster updates
      // Serve index.html for any unknown paths (essential for SPAs with client-side routing)
      historyApiFallback: true,
      open: true, // Open the default browser automatically when the server starts
    },

    // Plugins used during the build process
    plugins: [
      // Generates an HTML file, injects the bundle script, and uses index.html as a template
      new HtmlWebpackPlugin({
        template: './index.html', // Path to your source HTML file
        filename: 'index.html', // Name of the generated HTML file in the output directory
      }),
    ],

    // Performance hints configuration
    performance: {
      // Show warnings in production builds if bundle size exceeds limits
      hints: isProduction ? 'warning' : false,
    },
  };
};
