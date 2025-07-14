"""
audioProcessor.py

This script processes a music track to generate a remixed version with an optional shuffled intro and outro.

Features:
- Loads the input audio file ('audio.mp3').
- Uses Librosa to detect tempo (BPM) and beat positions.
- Optionally uses Madmom for more accurate tempo and beat tracking.
- Converts beat frames to actual time values.
- Separates audio into stems (vocals, drums, bass, other) using Spleeter (4 stems model).
- Identifies and selects the loudest segments from instrumental stems (bass, drums, other).
- Creates an intro by shuffling and stitching together the loudest instrumental segments.
- Optionally appends an outro using a similar shuffle method.
- Combines intro, original track, and optional outro into a single final remix.
- Saves the final output as 'output.mp3'.
- Also saves metadata (e.g., the shuffle order) in 'shuffle_info.json'.
"""

import sys
import os
import librosa
from pydub import AudioSegment
import json
import tempfile
import subprocess
import logging
import random

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def install_package(package):
    """Install a package using pip if it's not already installed."""
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", package])
        logger.info("Successfully installed %s", package)
    except Exception as e:
        logger.error("Failed to install %s: %s", package, str(e))
        raise


try:
    import madmom
except ImportError:
    logger.info("madmom not found, attempting to install...")
    install_package("madmom")
    import madmom

try:
    from spleeter.separator import Separator
except ImportError:
    logger.info("spleeter not found, attempting to install...")
    install_package("spleeter")
    from spleeter.separator import Separator


def detect_tempo_and_beats(audio_path, method="auto"):
    logger.info("Detecting tempo and beats using %s method", method)

    if method in ("librosa", "auto"):
        try:
            y, sr = librosa.load(audio_path, sr=None)
            tempo, beats = librosa.beat.beat_track(y=y, sr=sr)
            beat_times = librosa.frames_to_time(beats, sr=sr)

            if len(beats) > 0 and tempo > 0:
                logger.info(
                    "Librosa detected tempo: %s BPM with %s beats", tempo, len(beats))
                return tempo, beat_times
            elif method == "librosa":
                logger.warning(
                    "Librosa beat detection failed, but was explicitly requested")
                return None, None
        except Exception as e:
            logger.error("Error in librosa beat detection: %s", str(e))
            if method == "librosa":
                return None, None

    if method in ("madmom", "auto"):
        try:
            from madmom.features.beats import RNNBeatProcessor, BeatTrackingProcessor
            from madmom.features.tempo import TempoEstimationProcessor

            proc = RNNBeatProcessor()(audio_path)
            beats = BeatTrackingProcessor(fps=100)(proc)
            tempo_proc = TempoEstimationProcessor(fps=100)(proc)
            tempo = tempo_proc[0][0]

            logger.info(
                "Madmom detected tempo: %s BPM with %s beats", tempo, len(beats))
            return tempo, beats
        except Exception as e:
            logger.error("Error in madmom beat detection: %s", str(e))

    logger.warning("Beat detection failed with all methods")
    return None, None


def separate_audio_components(audio_path, output_dir):
    logger.info("Starting audio separation with Spleeter")

    try:
        separator = Separator('spleeter:4stems')
        main_song = AudioSegment.from_file(audio_path)
        separator.separate_to_file(audio_path, output_dir)

        base_name = os.path.splitext(os.path.basename(audio_path))[0]
        component_dir = os.path.join(output_dir, base_name)

        components = {
            'vocals': os.path.join(component_dir, 'vocals.wav'),
            'drums': os.path.join(component_dir, 'drums.wav'),
            'bass': os.path.join(component_dir, 'bass.wav'),
            'other': os.path.join(component_dir, 'other.wav')
        }

        for component, path in components.items():
            if not os.path.exists(path):
                logger.warning(
                    "Component %s file not found at %s", component, path)

        logger.info("Audio separation completed successfully")
        return [components, main_song]

    except Exception as e:
        logger.error("Error during audio separation: %s", str(e))
        return None


def pick_loudest_bars(stem, beats_ms, bars=4, beats_per_bar=4):
    total_beats = len(beats_ms)
    window = beats_per_bar * bars
    max_rms = -1
    pick_start = 0
    if total_beats < window + 1:
        return stem
    for i in range(total_beats - window):
        start_ms = int(beats_ms[i])
        end_ms = int(beats_ms[i + window])
        segment = stem[start_ms:end_ms]
        rms = segment.rms
        if rms > max_rms:
            max_rms = rms
            pick_start = i
    start_ms = int(beats_ms[pick_start])
    end_ms = int(beats_ms[pick_start + window])
    return stem[start_ms:end_ms]


def create_extended_mix(components, output_path, intro_bars, outro_bars, _preserve_vocals, _tempo, beat_times, main_song):
    logger.info(
        "Creating extended mix with %s bars intro and %s bars outro", intro_bars, outro_bars)

    try:
        beats_per_bar = 4
        intro_beats = intro_bars * beats_per_bar
        outro_beats = outro_bars * beats_per_bar

        if len(beat_times) < (intro_beats + outro_beats + 8):
            logger.warning(
                "Not enough beats detected (%s) for requested extension", len(beat_times))
            return False

        version = 1
        if "_v" in output_path:
            try:
                version = int(output_path.split("_v")[-1].split(".")[0])
            except (ValueError, IndexError):
                pass

        drums = AudioSegment.from_file(components['drums'])
        bass = AudioSegment.from_file(components['bass']) + 12
        other = AudioSegment.from_file(components['other']).apply_gain(9)
        vocals = AudioSegment.from_file(components['vocals'])

        beat_times_ms = [t * 1000 for t in beat_times]

        full_intro_drums = pick_loudest_bars(
            drums, beat_times_ms, bars=intro_bars)
        _unused_full_intro_bass = pick_loudest_bars(
            bass, beat_times_ms, bars=intro_bars)
        full_intro_other = pick_loudest_bars(
            other, beat_times_ms, bars=intro_bars)
        intro_vocals = pick_loudest_bars(
            vocals, beat_times_ms, bars=intro_bars)

        random.seed(version * 42)

        intro_labels = ['drums', 'other', 'drums', 'vocals']
        intro_segments = [full_intro_drums,
                          full_intro_other, full_intro_drums, intro_vocals]
        intro_zipped = list(zip(intro_labels, intro_segments))
        random.shuffle(intro_zipped)
        intro_components = [seg for (_, seg) in intro_zipped]
        shuffled_intro_order = [label for (label, _) in intro_zipped]
        random.seed()

        full_intro = sum(intro_components).fade_in(2000)

        extended_mix = full_intro.append(main_song, crossfade=500)

        extended_mix.export(
            output_path, format=os.path.splitext(output_path)[1][1:])
        logger.info(
            "Extended mix created successfully and saved to %s", output_path)

        output_base = os.path.splitext(os.path.basename(output_path))[0]
        save_dir = r"C:\Users\Dhanush\Desktop\softwareLabs"
        os.makedirs(save_dir, exist_ok=True)
        shuffle_json_path = os.path.join(
            save_dir, f"{output_base}_shuffle_order.json")
        shuffle_info = {
            "intro_shuffle_order": shuffled_intro_order
        }

        with open(shuffle_json_path, 'w') as f:
            json.dump(shuffle_info, f, indent=2)

        logger.info("Shuffle order saved to %s", shuffle_json_path)
        return True

    except Exception as e:
        logger.error("Error in create_extended_mix: %s", str(e))
        return False


def process_audio(input_path, output_path, intro_bars=16, outro_bars=16, preserve_vocals=True, beat_detection="auto"):

    logger.info("Starting audio processing: %s", input_path)
    logger.info(
        "Parameters: intro_bars=%s, outro_bars=%s, preserve_vocals=%s, beat_detection=%s", 
        intro_bars, outro_bars, preserve_vocals, beat_detection)

    try:

        intro_bars = int(intro_bars)
        outro_bars = int(outro_bars)
        preserve_vocals = str(preserve_vocals).lower() == 'true'

        with tempfile.TemporaryDirectory() as temp_dir:

            tempo, beat_times = detect_tempo_and_beats(
                input_path, method=beat_detection)
            if tempo is None or beat_times is None or len(beat_times) == 0:
                logger.error("Beat detection failed, cannot proceed")
                return False

            components, main_song = separate_audio_components(
                input_path, temp_dir)
            if components is None:
                logger.error("Audio separation failed, cannot proceed")
                return False

            success = create_extended_mix(
                components,
                output_path,
                intro_bars,
                outro_bars,
                preserve_vocals,
                tempo,
                beat_times,
                main_song
            )

            return success

    except Exception as e:
        logger.error("Error in audio processing: %s", str(e))
        return False


def main():
    """Main function to handle command line execution."""
    if len(sys.argv) < 3:
        print(
            "Usage: python audioProcessor.py <input_path> <output_path> [intro_bars] [outro_bars] [preserve_vocals] [beat_detection]")
        sys.exit(1)

    audio_input_path = sys.argv[1]
    audio_output_path = sys.argv[2]
    audio_intro_bars = int(sys.argv[3]) if len(sys.argv) > 3 else 16
    audio_outro_bars = int(sys.argv[4]) if len(sys.argv) > 4 else 16
    audio_preserve_vocals = sys.argv[5].lower(
    ) == 'true' if len(sys.argv) > 5 else True
    audio_beat_detection = sys.argv[6] if len(sys.argv) > 6 else "auto"

    processing_success = process_audio(audio_input_path, audio_output_path, audio_intro_bars,
                            audio_outro_bars, audio_preserve_vocals, audio_beat_detection)

    if processing_success:
        print(json.dumps({"status": "success", "output_path": audio_output_path}))
        sys.exit(0)
    else:
        print(json.dumps(
            {"status": "error", "message": "Failed to process audio"}))
        sys.exit(1)


if __name__ == "__main__":
    main()
