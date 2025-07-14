/**
 * Utility functions for audio processing and playback
 */

export interface AudioInfo {
  duration: number;
  format: string;
  sampleRate?: number;
  bitrate?: number;
}

/**
 * Convert seconds to formatted duration string (MM:SS)
 */
export function formatDuration(seconds: number): string {
  if (isNaN(seconds) || seconds === 0) return "--:--";
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = Math.floor(seconds % 60);
  return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
}

/**
 * Calculate bars from beats and time signature
 * @param beats Number of beats
 * @param timeSignature Time signature (e.g., 4 for 4/4)
 */
export function calculateBars(beats: number, timeSignature = 4): number {
  return Math.floor(beats / timeSignature);
}

/**
 * Calculate duration in seconds from tempo (BPM) and number of bars
 * @param bpm Tempo in beats per minute
 * @param bars Number of bars
 * @param timeSignature Time signature (e.g., 4 for 4/4)
 */
export function calculateDurationFromBars(bpm: number, bars: number, timeSignature = 4): number {
  // Duration = (bars * timeSignature * 60) / BPM
  return (bars * timeSignature * 60) / bpm;
}

/**
 * Check if a format is supported for upload
 */
export function isSupportedFormat(format: string): boolean {
  const supportedFormats = ['mp3', 'wav', 'flac', 'aiff'];
  return supportedFormats.includes(format.toLowerCase());
}

/**
 * Check if a file size is within upload limits
 */
export function isWithinSizeLimit(sizeInBytes: number, maxSizeMB = 15): boolean {
  return sizeInBytes <= maxSizeMB * 1024 * 1024;
}
