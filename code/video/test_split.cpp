/*
 * Copyright (c) 2015, Luca Fulchir<luker@fenrirproject.org>, All rights reserved.
 *
 * This file is part of "libRaptorQ".
 *
 * libRaptorQ is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 *
 * libRaptorQ is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * and a copy of the GNU Lesser General Public License
 * along with libRaptorQ.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <fstream>
#include <iostream>
#include <random>
#include "../src/RaptorQ.hpp"
#include <vector>
#include <time.h>
#include <opencv2/opencv.hpp>
#include <opencv2/highgui.hpp>
#include <opencv2/videoio.hpp>
using namespace std;
using namespace cv;

// Demonstration of how to use the C++ interface
// it's pretty simple, we generate some input,
// then encode, drop some packets (source and repair)
// and finally decode everything.


// mysize is bytes.
template <typename in_enc_align, typename out_enc_align, typename out_dec_align>
bool encode (std::vector<in_enc_align> myvec, mt19937_64 &rnd, float drop_prob,
														const uint8_t overhead);
template <typename in_enc_align, typename out_enc_align, typename out_dec_align>
bool decode (std::vector<std::pair<uint32_t, std::vector<out_enc_align>>> encoded, 
	uint64_t oti_common, uint64_t oti_scheme, const uint32_t mysize);

template <typename in_enc_align, typename out_enc_align, typename out_dec_align>
bool encode (std::vector<in_enc_align> myvec, mt19937_64 &rnd, float drop_prob,
														const uint8_t overhead)
{
	// define the alignment of the input and output data, for
	// decoder and encoder.
	// note that this is independent from the "mysize" argument,
	// which is always in bytes.
	// used as template arguments
	//typedef uint8_t			in_enc_align;
	//typedef uint16_t			out_enc_align;
	typedef out_enc_align	in_dec_align;
	//typedef uint32_t			out_dec_align;
	// NOTE:  out_enc_align is the same as in_dec_align so that we
	// can simulate data trnsmision just by passing along a vector, but
	// they do not need to be the same.

	//std::vector<in_enc_align> myvec;
	const uint32_t mysize = myvec.size();

	// initialize vector with random data
	// fill remaining data (more than "mysize" bytes) with zeros
	/*
	std::uniform_int_distribution<uint8_t> distr(0, 0xFF);
	myvec.reserve (static_cast<size_t> (
				std::ceil(static_cast<float> (mysize) / sizeof(in_enc_align))));
	in_enc_align tmp = 0;
	uint8_t shift = 0;
	for (uint32_t i = 0; i < mysize; ++i) {
		tmp += static_cast<in_enc_align> (distr(rnd)) << shift * 8;
		//tmp += static_cast<in_enc_align> (i) << shift * 8;
		++shift;
		if (shift >= sizeof(in_enc_align)) {
			myvec.push_back (tmp);
			shift = 0;
			tmp = 0;
		}
	}
	if (shift != 0)
		myvec.push_back (tmp);
*/
	// done initializing random data.



	// std::pair<symbol id (esi), symbol>
	std::vector<std::pair<uint32_t, std::vector<out_enc_align>>> encoded;

	// symbol and sub-symbol sizes
	// sub symbol must be multiple of alignment,
	// symbol must be multiple of subsymbol
	//std::uniform_int_distribution<uint16_t> sub_sym_distr (1, 16);
	//const uint16_t subsymbol = sizeof(in_enc_align) * sub_sym_distr(rnd);
	//std::uniform_int_distribution<uint16_t> sym_distr (1, 100);
	//const uint16_t symbol_size = subsymbol * sym_distr (rnd);
	const uint16_t subsymbol = sizeof(in_enc_align) * 16;	/*** speed ***/
	const uint16_t symbol_size = subsymbol * 100;	/*** speed ***/
	std::cout << "Subsymbol: " << subsymbol << " Symbol: " << symbol_size<<"\n";
	size_t aligned_symbol_size = static_cast<size_t> (
		std::ceil(static_cast<float> (symbol_size) / sizeof(out_enc_align)));
	auto enc_it = myvec.begin();

	//std::uniform_int_distribution<uint32_t> mem_distr (100, 200000);
	//RaptorQ::Encoder<typename std::vector<in_enc_align>::iterator,
	//						typename std::vector<out_enc_align>::iterator> enc (
	//			enc_it, myvec.end(), subsymbol, symbol_size, mem_distr(rnd));
	RaptorQ::Encoder<typename std::vector<in_enc_align>::iterator,
							typename std::vector<out_enc_align>::iterator> enc (
				enc_it, myvec.end(), subsymbol, symbol_size, 1000);	/*** speed ***/

	std::cout << "Size: " << mysize << " Blocks: " <<
									static_cast<int32_t>(enc.blocks()) << "\n";
	if (!enc) {
		std::cout << "Coud not initialize encoder.\n";
		return false;
	}

	enc.precompute(1, false);

	if (drop_prob > static_cast<float>(90.0))
		drop_prob = 90.0;	// this is still too high probably.
	std::uniform_real_distribution<float> drop (0.0, 100.0);

	int32_t repair;

	// start encoding
	int32_t blockid = -1;
	for (auto block : enc) {
		repair = overhead;
		++blockid;
		std::cout << "Block " << blockid << " with " << block.symbols() <<
																" symbols\n";
		// Now get the source and repair symbols.
		// make sure that at the end we end with "block.symbols() + overhead"
		// symbols, so that decoding is possible
		for (auto sym_it = block.begin_source(); sym_it != block.end_source();
																	++sym_it) {
			float dropped = drop (rnd);
			if (dropped <= drop_prob) {
				// we dropped one source symbol, we need one more repair.
				++repair;
				continue;
			}
			// create a place where to save our source symbol
			std::vector<out_enc_align> source_sym;
			source_sym.reserve (aligned_symbol_size);
			source_sym.insert (source_sym.begin(), aligned_symbol_size, 0);
			auto it = source_sym.begin();
			// save the symbol
			auto written = (*sym_it) (it, source_sym.end());
			if (written != aligned_symbol_size) {
				std::cout << written << "-vs-" << aligned_symbol_size <<
									" Could not get the whole source symbol!\n";
				return false;
			}
			// finally add it to the encoded vector
			encoded.emplace_back ((*sym_it).id(), std::move(source_sym));
		}
		// now get (overhead + source_symbol_lost) repair symbols.
		std::cout << "Source Packet lost: " << repair - overhead << "\n";
		auto sym_it = block.begin_repair();
		for (; repair >= 0 && sym_it != block.end_repair (block.max_repair());
																	++sym_it) {
			// repair symbols can be lost, too!
			float dropped = drop (rnd);
			if (dropped <= drop_prob) {
				continue;
			}
			--repair;
			// create a place where to save our source symbol
			std::vector<out_enc_align> repair_sym;
			repair_sym.reserve (aligned_symbol_size);
			repair_sym.insert (repair_sym.begin(), aligned_symbol_size, 0);
			auto it = repair_sym.begin();
			// save the repair symbol
			auto written = (*sym_it) (it, repair_sym.end());
			if (written != aligned_symbol_size) {
				std::cout << written << "-vs-" << aligned_symbol_size <<
									" bCould not get the whole repair symbol!\n";
				return false;
			}
			// finally add it to the encoded vector
			encoded.emplace_back ((*sym_it).id(), std::move(repair_sym));
		}
		if (sym_it == block.end_repair (block.max_repair())) {
			// we dropped waaaay too many symbols! how much are you planning to
			// lose, again???
			std::cout << "Maybe losing " << drop_prob << "% is too much?\n";
			return false;
		}
	}
	auto oti_scheme = enc.OTI_Scheme_Specific();
	auto oti_common = enc.OTI_Common();

	// encoding done. now "encoded" is the vector with the trnasmitted data.
	decode<in_enc_align, out_enc_align, out_dec_align>(encoded, oti_common, oti_scheme, mysize);

	return true;
}

template <typename in_enc_align, typename out_enc_align, typename out_dec_align>
bool decode (std::vector<std::pair<uint32_t, std::vector<out_enc_align>>> encoded, 
	uint64_t oti_common, uint64_t oti_scheme, const uint32_t mysize)
{
	
	// let's decode it
	typedef out_enc_align	in_dec_align;
	RaptorQ::Decoder<typename std::vector<in_dec_align>::iterator,
							typename std::vector<out_dec_align>::iterator>
												dec (oti_common, oti_scheme);

	std::vector<out_dec_align> received;
	size_t out_size = static_cast<size_t> (
				std::ceil(static_cast<float>(mysize) / sizeof(out_dec_align)));
	received.reserve (out_size);
	// make sure that there's enough place in "received" to get the
	// whole decoded data.
	for (uint32_t i = 0; i < out_size; ++i)
		received.push_back (static_cast<out_dec_align> (0));

	for (size_t i = 0; i < encoded.size(); ++i) {
		auto it = encoded[i].second.begin();
		if (!dec.add_symbol (it, encoded[i].second.end(), encoded[i].first))
			std::cout << "error adding?\n";
	}

	auto re_it = received.begin();
	// decode all blocks
	// you can actually call ".decode(...)" as many times
	// as you want. It will only start decoding once
	// it has enough data.
	auto decoded = dec.decode(re_it, received.end());

	if (decoded * sizeof(out_dec_align) < mysize) {
		if (decoded == 0) {
			std::cout << "Couldn't decode, RaptorQ Algorithm failure. Retry.\n";
			return true;
		} else {
			std::cout << "Partial Decoding? This should not have happened: " <<
					decoded * sizeof(out_dec_align) << " vs " << mysize << "\n";
		}
		return false;
	} else {
		std::cout << "Decoded: " << mysize << "\n";
	}

	Mat frame_received = Mat(480, 640, CV_8UC3);
	memcpy(frame_received.data, received.data(), received.size()*sizeof(uint8_t));
	cout << "received.size: " << received.size() << endl;
	imshow("frame_received", frame_received);
	waitKey(5000);

	return true;
}

int main (void)
{
	// get a random number generator
	std::mt19937_64 rnd;
	std::ifstream rand("/dev/random");
	uint64_t seed = 0;
	rand.read (reinterpret_cast<char *> (&seed), sizeof(seed));
	rand.close ();
	rnd.seed (seed);

	std::uniform_int_distribution<uint32_t> distr(1, 10000);

	char filename[20];
	strcpy(filename, "./image/test.jpg");
	Mat frame, frame_bgr[3];
	frame = imread(filename);
	if (frame.empty()) {
		printf("Could not load image\n");
		exit(0);
	}
	split(frame, frame_bgr);

	uint32_t frame_row = frame.rows;
	uint32_t frame_col = frame.cols;
	uint32_t frame_chan = frame.channels();
	uint32_t frame_size = frame_row * frame_col * frame_chan;
	printf("row:%i\tcol:%i\n", frame.rows, frame.cols);
	cout << "mat_size:" << frame.size() << endl;
	cout << "mat_type:" << frame.type() << endl;
	cout << "mat_total:" << frame.total() << endl;
	cout << "mat_elemSize:" << frame.elemSize() << endl;
	cout << "mat_depth:" << frame.depth() << endl;
	cout << "mat_channels:" << frame.channels() << endl;
	/* (1) */
	//uint8_t *mat_vec;
	//mat_vec = (uint8_t*) malloc(frame_size*sizeof(uint8_t));
	/* (1.1) */
	//mat_vec=(uint32_t*)(frame.data);
	/* (1.2) */
	//memcpy(mat_vec, frame.data, frame_size*sizeof(uint8_t));
	//Mat frame_covert(frame_row, frame_col, CV_8UC3, mat_vec);

	/* (2) */
	
	std::vector<uint8_t> mat_vec;
	if (frame.isContinuous()) {
		mat_vec.assign(frame.datastart, frame.dataend);
	} else {
		for (int i = 0; i < frame.rows; ++i) {
			mat_vec.insert(mat_vec.end(), frame.ptr<uint8_t>(i), frame.ptr<uint8_t>(i)+frame.cols);
		}
	}
	Mat frame_covert = Mat(frame_row, frame_col, CV_8UC3);
	/* (3) */
	/*
	std::vector<uint8_t> mat_vec;
	if (frame_bgr[0].isContinuous()) {
		mat_vec.assign(frame_bgr[0].datastart, frame_bgr[0].dataend);
	} else {
		for (int i = 0; i < frame_bgr[0].rows; ++i) {
			mat_vec.insert(mat_vec.end(), frame_bgr[0].ptr<uint8_t>(i), frame_bgr[0].ptr<uint8_t>(i)+frame_bgr[0].cols);
		}
	}
	Mat frame_covert = Mat(frame_row, frame_col, CV_8UC1);*/
	
	memcpy(frame_covert.data, mat_vec.data(), mat_vec.size()*sizeof(uint8_t));
	cout << "mat_vec.size: " << mat_vec.size() << endl;
	imshow("frame_covert", frame_covert);
	waitKey(500);

	// encode and decode
	//for (size_t i = 0; i < 1000; ++i) {
		bool ret;
		clock_t s_all, t_all;
		s_all = clock();
		time_t seconds;  
		seconds = time((time_t *)NULL); 
		ret = encode<uint8_t, uint32_t, uint8_t> (mat_vec, rnd, 10.0, 4);
		//ret = encode<uint8_t, uint32_t, uint8_t> (mat_vec.size()/3, rnd, 10.0, 4);
		if (!ret)
			return -1;
		cout <<time((time_t *)NULL) - seconds << endl;
		t_all = clock();
    	double duration=(double)(t_all - s_all) / CLOCKS_PER_SEC;
    	cout << duration << endl;

	//}
	std::cout << "All tests succesfull!\n";
	return 0;
}
