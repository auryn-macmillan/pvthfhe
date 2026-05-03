import matplotlib.pyplot as plt

def gen_placeholder():
    plt.figure()
    plt.text(0.5, 0.5, 'Placeholder Figure', ha='center', va='center')
    plt.savefig('placeholder.png')

if __name__ == "__main__":
    print("Placeholder figure script")
