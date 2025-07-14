/** @format */

import React from "react";

const Footer: React.FC = () => {
	return (
		<footer className='bg-gray-800 text-white mt-12 py-8'>
			<div className='container mx-auto px-4'>
				<div className='pt-4  border-gray-700 text-sm text-gray-400 text-center'>
					<p>
						© {new Date().getFullYear()} DJ Mix Extender. All rights reserved.
					</p>
				</div>
			</div>
		</footer>
	);
};

export default Footer;
