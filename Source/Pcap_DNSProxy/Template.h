// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2018 Chengr28
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either
// version 2 of the License, or (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.


#ifndef PCAP_DNSPROXY_TEMPLATE_H
#define PCAP_DNSPROXY_TEMPLATE_H

#include "Definition.h"

//////////////////////////////////////////////////
// Template definitions
// 
//Blocking queue class, please visit https://senlinzhan.github.io/2015/08/24/C-11%E5%B9%B6%E5%8F%91%E7%BC%96%E7%A8%8B%E5%85%AD.
template<typename Ty, typename Container = std::queue<Ty>> class BlockingQueue
{
public:
	using ContainerType = Container;
	using ValueType = typename Container::value_type;
	using Reference = typename Container::reference;
	using ConstReference = typename Container::const_reference;
	using SizeType = typename Container::size_type;
	using MutexType = std::mutex;
	using ConditionVariableType = std::condition_variable;

private:
	Container                OriginalQueue;
	MutexType                OriginalMutex;
	ConditionVariableType    OriginalConditionVariable;

public:
//Redefine operator functions
	BlockingQueue() = default;
	BlockingQueue(const BlockingQueue &) = delete;
	BlockingQueue & operator=(const BlockingQueue &) = delete;

//Pop function
	void pop(
		Reference Element)
	{
		std::unique_lock<MutexType> Lock(OriginalMutex);
		OriginalConditionVariable.wait(Lock, [this](){return !OriginalQueue.empty();});
		Element = std::move(OriginalQueue.front());
		OriginalQueue.pop();

		return;
	}

//Try to pop function
	bool try_pop(
		Reference Element)
	{
		std::lock_guard<MutexType> Lock(OriginalMutex);
		if (OriginalQueue.empty())
			return false;
		Element = std::move(OriginalQueue.front());
		OriginalQueue.pop();

		return true;
	}

//Empty check function
	bool empty(
		void) const
	{
		std::lock_guard<MutexType> Lock(OriginalMutex);
		return OriginalQueue.empty();
	}

//Size return function
	SizeType size(
		void) const
	{
		std::lock_guard<MutexType> Lock(OriginalMutex);
		return OriginalQueue.size();
	}

//Push function
	void push(
		const ValueType &Element)
	{
		std::unique_lock<MutexType> Lock(OriginalMutex);
		OriginalQueue.push(Element);
		Lock.unlock();
		OriginalConditionVariable.notify_one();

		return;
	}

//Push function
	void push(
		ValueType &&Element)
	{
		std::unique_lock<MutexType> Lock(OriginalMutex);
		OriginalQueue.push(std::move(Element));
		Lock.unlock();
		OriginalConditionVariable.notify_one();

		return;
	}
};
template<typename Ty> using BLOCKING_QUEUE = BlockingQueue<Ty>;

#if defined(ENABLE_LIBSODIUM)
//DNSCurveHeapBufferTable template class
template<typename Ty> class DNSCurveHeapBufferTable
{
public:
	Ty                                   *Buffer;
	size_t                               BufferSize;

//Redefine operator functions
//	DNSCurveHeapBufferTable() = default;
	DNSCurveHeapBufferTable(const DNSCurveHeapBufferTable &) = delete;
	DNSCurveHeapBufferTable & operator=(const DNSCurveHeapBufferTable &) = delete;

//Member functions
	DNSCurveHeapBufferTable(
		void);
	explicit DNSCurveHeapBufferTable(
		const size_t Size);
	DNSCurveHeapBufferTable(
		const size_t Count, 
		const size_t Size);
	void Swap(
		DNSCurveHeapBufferTable &Other);
	~DNSCurveHeapBufferTable(
		void);
};
template<typename Ty> using DNSCURVE_HEAP_BUFFER_TABLE = DNSCurveHeapBufferTable<Ty>;

//Template functions
//DNSCurveHeapBufferTable template class constructor
template<typename Ty> DNSCurveHeapBufferTable<Ty>::DNSCurveHeapBufferTable(
	void)
{
	Buffer = nullptr;
	BufferSize = 0;

	return;
}

//DNSCurveHeapBufferTable template class constructor
template<typename Ty> DNSCurveHeapBufferTable<Ty>::DNSCurveHeapBufferTable(
	const size_t Size)
{
	Buffer = reinterpret_cast<Ty *>(sodium_malloc(Size));
	if (Buffer != nullptr)
	{
		sodium_memzero(Buffer, Size);
		BufferSize = Size;
	}
	else {
		exit(EXIT_FAILURE);
	}

	return;
}

//DNSCurveHeapBufferTable template class constructor
template<typename Ty> DNSCurveHeapBufferTable<Ty>::DNSCurveHeapBufferTable(
	const size_t Count, 
	const size_t Size)
{
	Buffer = reinterpret_cast<Ty *>(sodium_allocarray(Count, Size));
	if (Buffer != nullptr)
	{
		sodium_memzero(Buffer, Count * Size);
		BufferSize = Count * Size;
	}
	else {
		exit(EXIT_FAILURE);
	}

	return;
}

//DNSCurveHeapBufferTable template class Swap function
template<typename Ty> void DNSCurveHeapBufferTable<Ty>::Swap(
	DNSCurveHeapBufferTable &Other)
{
	const auto BufferTemp = Buffer;
	Buffer = Other.Buffer;
	Other.Buffer = BufferTemp;
	const auto BufferSizeTemp = BufferSize;
	BufferSize = Other.BufferSize;
	Other.BufferSize = BufferSizeTemp;

	return;
}

//DNSCurveHeapBufferTable template class destructor
template<typename Ty> DNSCurveHeapBufferTable<Ty>::~DNSCurveHeapBufferTable(
	void)
{
	sodium_free(Buffer);
	Buffer = nullptr;
	BufferSize = 0;

	return;
}
#endif
#endif
