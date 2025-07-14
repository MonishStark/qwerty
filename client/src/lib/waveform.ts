/**
 * Utility functions for waveform visualization
 */

interface WaveformOptions {
  container: HTMLElement;
  waveColor?: string;
  progressColor?: string;
  height?: number;
  barWidth?: number;
  barGap?: number;
  responsive?: boolean;
}

/**
 * Generate a simple waveform visualization from audio data
 * Note: This is a simplified version. In a production app, use WaveSurfer.js
 */
export function generateSimpleWaveform(
  audioData: Float32Array | number[],
  options: WaveformOptions
): void {
  const { container, waveColor = '#4F46E5', progressColor = '#6366F1', height = 100, barWidth = 3, barGap = 1 } = options;
  
  // Clear container
  container.innerHTML = '';
  container.style.height = `${height}px`;
  container.style.display = 'flex';
  container.style.alignItems = 'center';
  container.style.overflowX = 'auto';
  
  // Calculate how many bars fit in the container
  const containerWidth = container.clientWidth;
  const barsCount = Math.floor(containerWidth / (barWidth + barGap));
  
  // Sample the audio data to fit the number of bars
  const dataStep = Math.floor(audioData.length / barsCount);
  
  // Create bars
  for (let i = 0; i < barsCount; i++) {
    const index = Math.min(i * dataStep, audioData.length - 1);
    const value = Math.abs(audioData[index]);
    const barHeight = Math.max(1, Math.floor(value * height));
    
    const bar = document.createElement('div');
    bar.style.width = `${barWidth}px`;
    bar.style.marginRight = `${barGap}px`;
    bar.style.height = `${barHeight}px`;
    bar.style.backgroundColor = waveColor;
    bar.style.borderRadius = '1px';
    
    container.appendChild(bar);
  }
}

/**
 * Generate a random waveform for display purposes
 * Note: This should only be used for UI mockups when no real data is available
 */
export function generateRandomWaveform(options: WaveformOptions): void {
  const { container, height = 100, barWidth = 3, barGap = 1 } = options;
  
  // Clear container
  container.innerHTML = '';
  
  // Calculate how many bars fit in the container
  const containerWidth = container.clientWidth;
  const barsCount = Math.floor(containerWidth / (barWidth + barGap));
  
  // Create random data
  const randomData = Array(barsCount).fill(0).map(() => Math.random());
  
  // Create waveform
  generateSimpleWaveform(randomData, options);
}

/**
 * Update progress on a simple waveform
 */
export function updateWaveformProgress(container: HTMLElement, progress: number, progressColor = '#6366F1'): void {
  const bars = container.children;
  const progressIndex = Math.floor(bars.length * progress);
  
  for (let i = 0; i < bars.length; i++) {
    const bar = bars[i] as HTMLElement;
    bar.style.backgroundColor = i <= progressIndex ? progressColor : '#4F46E5';
  }
}
