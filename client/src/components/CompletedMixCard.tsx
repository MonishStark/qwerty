/** @format */

import React from "react";
import { AudioTrack } from "@shared/schema";
import { formatDuration } from "@/lib/audio";

interface CompletedMixCardProps {
	track: AudioTrack;
	onPreview: () => void;
	onAdjust: () => void;
}

const CompletedMixCard: React.FC<CompletedMixCardProps> = ({
	track,
	onPreview,
	onAdjust,
}) => {
	// Only show if track is successfully processed
	if (track.status !== "completed" || !track.extendedPath) {
		return null;
	}

	const handleDownload = () => {
		window.location.href = `/api/tracks/${track.id}/download`;
	};

	return (
		<div className='bg-white rounded-xl shadow-md p-6 mt-6'>
			<div className='flex justify-between items-start mb-4'>
				<h2 className='text-xl font-semibold'>Extended Mix Ready</h2>
				<span className='inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800'>
					<span className='material-icons text-sm mr-1'>check_circle</span>
					Completed
				</span>
			</div>

			<div className='flex flex-col sm:flex-row items-center sm:items-start gap-4 mb-4 p-4 bg-gray-50 rounded-lg'>
				<div className='flex-shrink-0'>
					<div className='w-24 h-24 bg-gradient-to-br from-primary to-purple-600 rounded-lg flex items-center justify-center shadow-md'>
						<span className='material-icons text-white text-3xl'>
							equalizer
						</span>
					</div>
				</div>

				<div className='flex-1 text-center sm:text-left'>
					<h3 className='text-lg font-bold'>
						{track.originalFilename.replace(/\.[^/.]+$/, "")} (Extended Mix v$
						{track.extendedPaths?.length || 1})
						{track.originalFilename.match(/\.[^/.]+$/)?.[0] || ""}
					</h3>
					<p className='text-gray-500 mb-2'>
						Extended • {formatDuration(track.extendedDuration || 0)} •{" "}
						{track.bpm || "--"} BPM
					</p>

					<div className='text-sm text-gray-600 mb-3'>
						<p>
							DJ-friendly with {track.settings?.introLength || 16}-bar intro and{" "}
							{track.settings?.outroLength || 16}-bar outro
						</p>
						<p>Ideal for mixing, with clean transition points</p>
					</div>

					<div className='flex flex-wrap gap-2 justify-center sm:justify-start'>
						<button
							className='inline-flex items-center px-3 py-1.5 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-primary hover:bg-primary-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary'
							onClick={handleDownload}>
							<span className='material-icons text-sm mr-1'>download</span>
							Download
						</button>
						<button
							className='inline-flex items-center px-3 py-1.5 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary'
							onClick={onPreview}>
							<span className='material-icons text-sm mr-1'>play_arrow</span>
							Preview
						</button>
						<button
							className='inline-flex items-center px-3 py-1.5 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary'
							onClick={onAdjust}>
							<span className='material-icons text-sm mr-1'>settings</span>
							Adjust
						</button>
					</div>
				</div>
			</div>

			<div>
				<h4 className='font-medium mb-2'>Structure Comparison</h4>
				<div className='grid grid-cols-1 md:grid-cols-2 gap-4'>
					<div>
						<p className='text-sm font-medium mb-1'>Original</p>
						<div className='h-10 w-full bg-gray-200 rounded overflow-hidden flex'>
							<div className='w-4/5 bg-gray-600 flex-shrink-0 flex items-center justify-center text-xs text-white'>
								Main Song
							</div>
							<div className='w-1/5 bg-gray-400 flex-shrink-0 flex items-center justify-center text-xs text-white'>
								Outro
							</div>
						</div>
					</div>
					<div>
						<p className='text-sm font-medium mb-1'>Extended Version</p>
						<div className='h-10 w-full bg-gray-200 rounded overflow-hidden flex'>
							<div className='w-1/5 bg-primary flex-shrink-0 flex items-center justify-center text-xs text-white'>
								Intro
							</div>
							<div className='w-3/5 bg-gray-600 flex-shrink-0 flex items-center justify-center text-xs text-white rounded-sm'>
								Main Song
							</div>
						</div>
					</div>
				</div>
			</div>
		</div>
	);
};

export default CompletedMixCard;
