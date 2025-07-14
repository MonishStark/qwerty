"""
utils.py

This script analyzes an audio file and extracts useful metadata, including:
- Audio format
- Duration in seconds
- Bitrate
- Estimated tempo (BPM)
- Detected musical key

It uses librosa and pydub for audio analysis and handles errors gracefully with a fallback mechanism.
Run the script from the command line with a file path, and it outputs JSON-formatted metadata.
"""

import sys
import json
import logging

import librosa
import numpy as np
from os import path
from pydub import AudioSegment

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def get_audio_format(file_path):
    return path.splitext(file_path)[1][1:].lower()


def get_audio_data(file_path):
    return librosa.load(file_path, sr=None)


def get_audio_duration(audio_array, sample_rate):
    return librosa.get_duration(y=audio_array, sr=sample_rate)


def get_audio_bitrate(audio):
    return audio.frame_rate * audio.sample_width * audio.channels * 8


def get_audio_tempo(audio_array, sample_rate):
    onset_env = librosa.onset.onset_strength(y=audio_array, sr=sample_rate)
    return librosa.beat.tempo(onset_envelope=onset_env, sr=sample_rate)[0]


def detect_key(audio_array, sample_rate):
    chroma = librosa.feature.chroma_cqt(y=audio_array, sr=sample_rate)
    chroma_sum = np.sum(chroma, axis=1)
    key_idx = np.argmax(chroma_sum)

    key_names = ['C', 'C#', 'D', 'D#', 'E', 'F',
                 'F#', 'G', 'G#', 'A', 'A#', 'B']
    key = key_names[key_idx]

    minor_chroma = librosa.feature.chroma_cqt(
        y=audio_array, sr=sample_rate, bins_per_octave=36)
    minor_sum = np.sum(minor_chroma[9:], axis=1) / np.sum(minor_chroma, axis=1)

    key_type = "minor" if np.mean(minor_sum) > 0.2 else "major"
    return f"{key} {key_type}"


def analyze_audio_file(file_path):
    logger.info("Analyzing audio file: %s", file_path)

    try:
        logger.info("Starting audio analysis...")
        format_type = get_audio_format(file_path)

        audio_array, sample_rate = get_audio_data(file_path)
        duration = int(get_audio_duration(audio_array, sample_rate))

        audio = AudioSegment.from_file(file_path)
        bitrate = int(get_audio_bitrate(audio))

        tempo = int(round(get_audio_tempo(audio_array, sample_rate)))
        key = detect_key(audio_array, sample_rate)

        info = {
            "format": format_type,
            "duration": duration,
            "bpm": tempo,
            "key": key,
            "bitrate": bitrate
        }

        logger.info("Successfully analyzed audio file: %s", info)
        return info

    except Exception as error:
        logger.error("Error analyzing audio file: %s", str(error))
        return fallback_audio_analysis(file_path)


def fallback_audio_analysis(file_path):
    try:
        audio = AudioSegment.from_file(file_path)
        format_type = get_audio_format(file_path)

        return {
            "format": format_type,
            "duration": int(len(audio) / 1000),
            "bpm": 0,
            "key": "Unknown",
            "bitrate": int(get_audio_bitrate(audio))
        }

    except Exception as error:
        logger.error("Fallback analysis failed: %s", str(error))

        return {
            "format": get_audio_format(file_path),
            "duration": 0,
            "bpm": 0,
            "key": "Unknown",
            "bitrate": 0
        }


def is_valid_filepath(file_path):
    return path.exists(file_path)


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No file path provided"}))
        sys.exit(1)

    file_path = sys.argv[1]

    if not is_valid_filepath(file_path):
        print(json.dumps({"error": f"File not found: {file_path}"}))
        sys.exit(1)

    info = analyze_audio_file(file_path)
    print(json.dumps(info))


if __name__ == "__main__":
    main()
