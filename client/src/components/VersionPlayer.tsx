/** @format */

import React, { useState, useRef, useEffect } from "react";
import { AudioTrack } from "@shared/schema";
import { formatDuration } from "@/lib/audio";

interface VersionPlayerProps {
	track: AudioTrack;
	version: number;
}

const VersionPlayer: React.FC<VersionPlayerProps> = ({ track, version }) => {
	const [isPlaying, setIsPlaying] = useState(false);
	const [currentTime, setCurrentTime] = useState(0);
	const [duration, setDuration] = useState(0);
	const audioRef = useRef<HTMLAudioElement>(null);
	const progressIntervalRef = useRef<number>();

	useEffect(() => {
		if (audioRef.current) {
			const audio = audioRef.current;

			const updateTime = () => {
				setCurrentTime(audio.currentTime);
			};

			const onLoadedMetadata = () => {
				setDuration(audio.duration);
			};

			const onEnded = () => {
				setIsPlaying(false);
				setCurrentTime(0);
				clearInterval(progressIntervalRef.current);
			};

			audio.addEventListener("loadedmetadata", onLoadedMetadata);
			audio.addEventListener("ended", onEnded);

			return () => {
				audio.removeEventListener("loadedmetadata", onLoadedMetadata);
				audio.removeEventListener("ended", onEnded);
				clearInterval(progressIntervalRef.current);
			};
		}
	}, []);

	const togglePlayPause = () => {
		if (!audioRef.current) return;

		if (isPlaying) {
			audioRef.current.pause();
			clearInterval(progressIntervalRef.current);
			setIsPlaying(false);
		} else {
			audioRef.current.play();
			progressIntervalRef.current = window.setInterval(() => {
				if (audioRef.current) {
					setCurrentTime(audioRef.current.currentTime);
				}
			}, 100);
			setIsPlaying(true);
		}
	};

	const handleSkipBack = () => {
		if (!audioRef.current) return;
		audioRef.current.currentTime = Math.max(
			0,
			audioRef.current.currentTime - 10
		);
		setCurrentTime(audioRef.current.currentTime);
	};

	const handleSkipForward = () => {
		if (!audioRef.current) return;
		audioRef.current.currentTime = Math.min(
			audioRef.current.duration,
			audioRef.current.currentTime + 10
		);
		setCurrentTime(audioRef.current.currentTime);
	};

	return (
		<div className='bg-gray-50 rounded-lg p-4 mb-4'>
			<div className='flex justify-between items-center mb-4'>
				<div className='text-lg font-medium'>Version {version + 1}</div>
				<a
					href={`/api/tracks/${track.id}/download?version=${version}`}
					className='inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-primary hover:bg-primary-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary'
					download>
					<span className='material-icons text-sm mr-1 mt-1'>download</span>
					Download
				</a>
			</div>

			<div className='waveform-container bg-gray-900 rounded-lg'>
				<div className='waveform'>
					<div className='waveform-bars flex items-center h-full p-4'>
						{Array(150)
							.fill(0)
							.map((_, i) => {
								const originalLength = track.duration || 0;
								const extendedLength =
									track.extendedDurations?.[version] ||
									track.extendedDuration ||
									duration;
								const introLength = Math.max(
									0,
									extendedLength - originalLength
								);
								const introSection = (introLength / extendedLength) * 150;

								const isIntroSection = i <= introSection;
								const isCurrentlyPlaying = i / 150 <= currentTime / duration;
								return (
									<div
										key={`version-${version}-waveform-${i}`}
										className='waveform-bar transition-colors duration-300'
										style={{
											height: `${Math.floor(Math.random() * 70 + 10)}px`,
											width: "3px",
											margin: "0 1px",
											background: isCurrentlyPlaying
												? isIntroSection
													? "linear-gradient(to top, #10b981, #34d399)" // Playing intro (green)
													: "linear-gradient(to top, #7c3aed, #a78bfa)" // Playing main (purple)
												: isIntroSection
												? "linear-gradient(to top, #064e3b, #065f46)" // Unplayed intro (dark green)
												: "linear-gradient(to top, #4c1d95, #5b21b6)", // Unplayed main (dark purple)
										}}></div>
								);
							})}
					</div>
				</div>
			</div>

			<div
				className='player-progress mt-2 mb-2 h-2 bg-gray-200 rounded-full overflow-hidden cursor-pointer'
				onClick={(e) => {
					if (!audioRef.current) return;
					const rect = e.currentTarget.getBoundingClientRect();
					const pos = (e.clientX - rect.left) / rect.width;
					const newTime = pos * duration;
					audioRef.current.currentTime = newTime;
					setCurrentTime(newTime);
				}}>
				<div
					className='h-full bg-gradient-to-r from-purple-600 to-purple-400 transition-all duration-300'
					style={{
						width: `${(currentTime / (duration || 1)) * 100}%`,
					}}
				/>
			</div>

			<div className='player-controls flex items-center'>
				<button
					className='p-2 rounded-full hover:bg-gray-200'
					onClick={handleSkipBack}>
					<span className='material-icons'>skip_previous</span>
				</button>
				<button
					className='p-2 rounded-full hover:bg-gray-200'
					onClick={togglePlayPause}>
					<span className='material-icons'>
						{isPlaying ? "pause" : "play_arrow"}
					</span>
				</button>
				<button
					className='p-2 rounded-full hover:bg-gray-200'
					onClick={handleSkipForward}>
					<span className='material-icons'>skip_next</span>
				</button>
				<span className='text-sm text-gray-500 ml-2 -mt-2'>
					{formatDuration(currentTime)} / {formatDuration(duration)}
				</span>
			</div>

			<audio
				ref={audioRef}
				src={`/api/audio/${track.id}/extended?version=${version}`}
				preload='metadata'
				onLoadedMetadata={(e) =>
					setDuration((e.target as HTMLAudioElement).duration)
				}
				style={{ display: "none" }}
			/>
		</div>
	);
};

export default VersionPlayer;
