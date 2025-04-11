// webpack.config.js for Web App
const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin'); // Import plugin

module.exports = (env, argv) => {
  // Use function form to access mode
  const isProduction = argv.mode === 'production';

  return {
    // Entry point
    entry: './src/index.tsx',
    output: {
      filename: isProduction ? 'bundle.[contenthash].js' : 'bundle.js', // Add hash for production builds
      path: path.resolve(__dirname, 'dist'),
      publicPath: '/',
      clean: true,
    },
    // Target the web environment
    target: 'web',
    mode: isProduction ? 'production' : 'development', // Set mode based on command
    module: {
      rules: [
        {
          test: /\.(ts|tsx|js|jsx)$/,
          exclude: /node_modules/,
          use: {
            loader: 'babel-loader',
            options: {
              presets: [
                '@babel/preset-env',
                ['@babel/preset-react', { runtime: 'automatic' }],
                '@babel/preset-typescript',
              ],
            },
          },
        },
        {
          test: /\.css$/i,
          use: [
            'style-loader', // Injects styles into DOM
            'css-loader', // Resolves CSS imports
            'postcss-loader', // Processes CSS with PostCSS (Tailwind)
          ],
        },
      ],
    },
    resolve: {
      extensions: ['.tsx', '.ts', '.js', '.jsx'],
      alias: {
        // Keep the alias for shadcn imports
        '@': path.resolve(__dirname, 'src'),
      },
    },
    // Source maps for debugging
    devtool: isProduction ? 'source-map' : 'inline-source-map',

    // *** Configuration for webpack-dev-server ***
    devServer: {
      static: {
        directory: path.join(__dirname, 'public'),
      },
      compress: true, // Enable gzip compression
      port: 3000, // <<< Port for the dev server (change here if needed)
      hot: true, // Enable Hot Module Replacement (HMR)
      historyApiFallback: true, // Serve index.html for SPA routing (important for React Router if used)
      open: true, // Open browser automatically
    },
    plugins: [
      // Automatically generates index.html and injects the bundle
      new HtmlWebpackPlugin({
        template: './index.html', // Use your existing index.html as a template
        filename: 'index.html',
      }),
    ],
    performance: {
      hints: isProduction ? 'warning' : false, // Show performance hints in production
    },
  };
};
